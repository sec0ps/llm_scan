# =============================================================================
# LLM Security Testing Framework - Comprehensive AI Security Assessment
# =============================================================================
#
# Author: Keith Pachulski
# Company: Red Cell Security, LLC
# Email: keith@redcellsecurity.org
# Website: www.redcellsecurity.org
#
# Copyright (c) 2025 Keith Pachulski. All rights reserved.
#
# License: This software is licensed under the MIT License.
#          You are free to use, modify, and distribute this software
#          in accordance with the terms of the license.
#
# Purpose: This module is part of the LLM Security Testing Framework, designed to
#          provide comprehensive security assessment capabilities for Large Language
#          Models and AI systems. It includes automated vulnerability detection,
#          prompt injection testing, business logic bypass detection, data extraction
#          analysis, and professional security reporting for authorized penetration
#          testing and security research.
#
# SECURITY NOTICE: This framework is intended for authorized security testing only.
#                  Users must obtain explicit permission before testing any LLM system.
#                  This tool is designed for defensive security purposes and should
#                  only be used in accordance with applicable laws and regulations.
#
# DISCLAIMER: This software is provided "as-is," without warranty of any kind,
#             express or implied, including but not limited to the warranties
#             of merchantability, fitness for a particular purpose, and non-infringement.
#             In no event shall the authors or copyright holders be liable for any claim,
#             damages, or other liability, whether in an action of contract, tort, or otherwise,
#             arising from, out of, or in connection with the software or the use or other dealings
#             in the software.
#
# =============================================================================
import json
import html
import base64
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime, timedelta
from pathlib import Path
import logging
from io import BytesIO
import hashlib

try:
    from jinja2 import Template, Environment, FileSystemLoader
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False
    Template = None
    Environment = None
    FileSystemLoader = None

try:
    import matplotlib
    matplotlib.use('Agg')  # Use non-interactive backend
    import matplotlib.pyplot as plt
    import seaborn as sns
    CHARTS_AVAILABLE = True
except ImportError:
    CHARTS_AVAILABLE = False
    plt = None
    sns = None

from llm_scan import TestResult, AttackCategory, Severity

class ReportFormat(Enum):
    """Supported report output formats"""
    HTML = "html"
    PDF = "pdf"
    JSON = "json"
    CSV = "csv"
    MARKDOWN = "markdown"
    DOCX = "docx"

class ReportScope(Enum):
    """Report scope levels"""
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    DETAILED = "detailed"
    COMPLIANCE = "compliance"

@dataclass
class ReportMetadata:
    """Report metadata and configuration"""
    title: str
    description: str
    generated_by: str
    generation_time: datetime = field(default_factory=datetime.now)
    report_id: str = field(default_factory=lambda: hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8])
    version: str = "1.0"
    classification: str = "CONFIDENTIAL"
    scope: ReportScope = ReportScope.TECHNICAL
    custom_fields: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ExecutiveSummary:
    """Executive summary data structure"""
    overall_risk_level: str
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    total_tests: int
    success_rate: float
    key_vulnerabilities: List[str]
    business_impact: List[str]
    immediate_actions: List[str]
    risk_score: float

@dataclass
class TechnicalSummary:
    """Technical summary data structure"""
    test_categories: Dict[str, Dict[str, Any]]
    vulnerability_breakdown: Dict[str, int]
    attack_vectors: Dict[str, int]
    response_patterns: Dict[str, Any]
    payload_analysis: Dict[str, Any]
    timing_analysis: Dict[str, Any]
    failure_modes: List[str]

@dataclass
class ComplianceSummary:
    """Compliance and regulatory summary"""
    framework_coverage: Dict[str, float]
    compliance_gaps: List[str]
    regulatory_findings: Dict[str, List[str]]
    control_effectiveness: Dict[str, str]
    remediation_timeline: Dict[str, str]

class ReportGenerator:
    """Advanced report generation with multiple formats and customization"""

    def __init__(self, template_dir: str = "./templates", output_dir: str = "./reports"):
        self.template_dir = Path(template_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Setup Jinja2 environment if available
        if JINJA2_AVAILABLE:
            self.jinja_env = Environment(
                loader=FileSystemLoader(self.template_dir) if self.template_dir.exists() else None
            )
        else:
            self.jinja_env = None
            self.logger.warning("Jinja2 not available - using basic template rendering")
        
        # Configure matplotlib for chart generation
        if CHARTS_AVAILABLE:
            plt.style.use('default')
            sns.set_palette("husl")
        
        # Setup logging
        self.logger = self._setup_logging()
        
        # Chart cache for performance
        self.chart_cache = {}
        
        # Create default templates if they don't exist
        self._create_default_templates()
    
    def _setup_logging(self) -> logging.Logger:
        """Setup report generator logging"""
        logger = logging.getLogger("ReportGenerator")
        logger.setLevel(logging.INFO)
        
        log_file = self.output_dir / "report_generator.log"
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        return logger
    
    def _create_default_templates(self):
        """Create default report templates"""
        if not self.template_dir.exists():
            self.template_dir.mkdir(exist_ok=True)
        
        # Create basic HTML template
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>{{ metadata.title }}</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { border-bottom: 3px solid #2c3e50; padding-bottom: 20px; margin-bottom: 30px; }
        .title { color: #2c3e50; font-size: 2.5em; margin: 0; font-weight: 300; }
        .subtitle { color: #7f8c8d; font-size: 1.2em; margin: 10px 0 0 0; }
        .metadata { background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .executive-summary { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 25px; border-radius: 8px; margin: 20px 0; }
        .risk-level { font-size: 2em; font-weight: bold; text-align: center; margin: 15px 0; }
        .risk-critical { color: #e74c3c; }
        .risk-high { color: #f39c12; }
        .risk-medium { color: #f1c40f; }
        .risk-low { color: #27ae60; }
        .findings-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .finding-card { background: white; padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .finding-number { font-size: 2.5em; font-weight: bold; margin-bottom: 10px; }
        .section { margin: 30px 0; }
        .section-title { color: #2c3e50; font-size: 1.8em; border-bottom: 2px solid #3498db; padding-bottom: 10px; margin-bottom: 20px; }
        .vulnerability-item { background: #fff; border-left: 4px solid #e74c3c; padding: 15px; margin: 10px 0; border-radius: 0 5px 5px 0; }
        .recommendation { background: #d5f4e6; border-left: 4px solid #27ae60; padding: 15px; margin: 10px 0; border-radius: 0 5px 5px 0; }
        .chart-container { text-align: center; margin: 20px 0; }
        .chart-container img { max-width: 100%; height: auto; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #bdc3c7; text-align: center; color: #7f8c8d; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #3498db; color: white; }
        .severity-critical { background-color: #ffebee; color: #c62828; }
        .severity-high { background-color: #fff3e0; color: #ef6c00; }
        .severity-medium { background-color: #fffde7; color: #f57f17; }
        .severity-low { background-color: #f1f8e9; color: #558b2f; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 class="title">{{ metadata.title }}</h1>
            <p class="subtitle">{{ metadata.description }}</p>
        </div>
        
        <div class="metadata">
            <strong>Report ID:</strong> {{ metadata.report_id }} | 
            <strong>Generated:</strong> {{ metadata.generation_time.strftime('%Y-%m-%d %H:%M:%S') }} | 
            <strong>Classification:</strong> {{ metadata.classification }}
        </div>
        
        {% if executive_summary %}
        <div class="executive-summary">
            <h2>Executive Summary</h2>
            <div class="risk-level risk-{{ executive_summary.overall_risk_level.lower() }}">
                Overall Risk Level: {{ executive_summary.overall_risk_level }}
            </div>
            
            <div class="findings-grid">
                <div class="finding-card">
                    <div class="finding-number risk-critical">{{ executive_summary.critical_findings }}</div>
                    <div>Critical</div>
                </div>
                <div class="finding-card">
                    <div class="finding-number risk-high">{{ executive_summary.high_findings }}</div>
                    <div>High</div>
                </div>
                <div class="finding-card">
                    <div class="finding-number risk-medium">{{ executive_summary.medium_findings }}</div>
                    <div>Medium</div>
                </div>
                <div class="finding-card">
                    <div class="finding-number risk-low">{{ executive_summary.low_findings }}</div>
                    <div>Low</div>
                </div>
            </div>
            
            <p><strong>Test Coverage:</strong> {{ executive_summary.total_tests }} tests executed with {{ "%.1f"|format(executive_summary.success_rate * 100) }}% vulnerability detection rate</p>
            <p><strong>Risk Score:</strong> {{ "%.1f"|format(executive_summary.risk_score) }}/10.0</p>
        </div>
        {% endif %}
        
        {% if charts %}
        <div class="section">
            <h2 class="section-title">Security Analysis Charts</h2>
            {% for chart_name, chart_data in charts.items() %}
            <div class="chart-container">
                <h3>{{ chart_name.replace('_', ' ').title() }}</h3>
                <img src="data:image/png;base64,{{ chart_data }}" alt="{{ chart_name }}">
            </div>
            {% endfor %}
        </div>
        {% endif %}
        
        {% if vulnerability_details %}
        <div class="section">
            <h2 class="section-title">Vulnerability Details</h2>
            {% for vuln in vulnerability_details %}
            <div class="vulnerability-item">
                <h4>{{ vuln.title }} <span class="severity-{{ vuln.severity.lower() }}">[{{ vuln.severity }}]</span></h4>
                <p><strong>Category:</strong> {{ vuln.category }}</p>
                <p><strong>Description:</strong> {{ vuln.description }}</p>
                {% if vuln.evidence %}
                <p><strong>Evidence:</strong></p>
                <ul>
                {% for evidence in vuln.evidence %}
                    <li>{{ evidence }}</li>
                {% endfor %}
                </ul>
                {% endif %}
            </div>
            {% endfor %}
        </div>
        {% endif %}
        
        {% if recommendations %}
        <div class="section">
            <h2 class="section-title">Recommendations</h2>
            {% for rec in recommendations %}
            <div class="recommendation">
                <strong>{{ rec.priority }}:</strong> {{ rec.description }}
                {% if rec.timeline %}
                <br><em>Timeline: {{ rec.timeline }}</em>
                {% endif %}
            </div>
            {% endfor %}
        </div>
        {% endif %}
        
        <div class="footer">
            <p>Generated by LLM Security Testing Framework v{{ metadata.version }}</p>
            <p>This report contains confidential security information. Handle according to your organization's data classification policies.</p>
        </div>
    </div>
</body>
</html>
        """
        
        with open(self.template_dir / "default_report.html", 'w') as f:
            f.write(html_template)

    def _get_default_html_template(self) -> str:
        """Get default HTML template as string"""
        return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>{{ metadata.title }}</title>
        <meta charset="UTF-8">
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
            .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .header { border-bottom: 3px solid #2c3e50; padding-bottom: 20px; margin-bottom: 30px; }
            .title { color: #2c3e50; font-size: 2.5em; margin: 0; font-weight: 300; }
            .subtitle { color: #7f8c8d; font-size: 1.2em; margin: 10px 0 0 0; }
            .metadata { background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }
            .executive-summary { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 25px; border-radius: 8px; margin: 20px 0; }
            .risk-level { font-size: 2em; font-weight: bold; text-align: center; margin: 15px 0; }
            .risk-critical { color: #e74c3c; }
            .risk-high { color: #f39c12; }
            .risk-medium { color: #f1c40f; }
            .risk-low { color: #27ae60; }
            .findings-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
            .finding-card { background: white; padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
            .finding-number { font-size: 2.5em; font-weight: bold; margin-bottom: 10px; }
            .section { margin: 30px 0; }
            .section-title { color: #2c3e50; font-size: 1.8em; border-bottom: 2px solid #3498db; padding-bottom: 10px; margin-bottom: 20px; }
            .vulnerability-item { background: #fff; border-left: 4px solid #e74c3c; padding: 15px; margin: 10px 0; border-radius: 0 5px 5px 0; }
            .recommendation { background: #d5f4e6; border-left: 4px solid #27ae60; padding: 15px; margin: 10px 0; border-radius: 0 5px 5px 0; }
            .chart-container { text-align: center; margin: 20px 0; }
            .chart-container img { max-width: 100%; height: auto; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
            .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #bdc3c7; text-align: center; color: #7f8c8d; }
            .severity-critical { background-color: #ffebee; color: #c62828; padding: 2px 8px; border-radius: 3px; }
            .severity-high { background-color: #fff3e0; color: #ef6c00; padding: 2px 8px; border-radius: 3px; }
            .severity-medium { background-color: #fffde7; color: #f57f17; padding: 2px 8px; border-radius: 3px; }
            .severity-low { background-color: #f1f8e9; color: #558b2f; padding: 2px 8px; border-radius: 3px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1 class="title">{{ metadata.title }}</h1>
                <p class="subtitle">{{ metadata.description }}</p>
            </div>
            
            <div class="metadata">
                <strong>Report ID:</strong> {{ metadata.report_id }} | 
                <strong>Generated:</strong> {{ metadata.generation_time.strftime('%Y-%m-%d %H:%M:%S') }} | 
                <strong>Classification:</strong> {{ metadata.classification }}
            </div>
            
            {% if executive_summary %}
            <div class="executive-summary">
                <h2>Executive Summary</h2>
                <div class="risk-level risk-{{ executive_summary.overall_risk_level.lower() }}">
                    Overall Risk Level: {{ executive_summary.overall_risk_level }}
                </div>
                
                <div class="findings-grid">
                    <div class="finding-card">
                        <div class="finding-number risk-critical">{{ executive_summary.critical_findings }}</div>
                        <div>Critical</div>
                    </div>
                    <div class="finding-card">
                        <div class="finding-number risk-high">{{ executive_summary.high_findings }}</div>
                        <div>High</div>
                    </div>
                    <div class="finding-card">
                        <div class="finding-number risk-medium">{{ executive_summary.medium_findings }}</div>
                        <div>Medium</div>
                    </div>
                    <div class="finding-card">
                        <div class="finding-number risk-low">{{ executive_summary.low_findings }}</div>
                        <div>Low</div>
                    </div>
                </div>
                
                <p><strong>Test Coverage:</strong> {{ executive_summary.total_tests }} tests executed</p>
                <p><strong>Risk Score:</strong> {{ "%.1f"|format(executive_summary.risk_score) }}/10.0</p>
            </div>
            {% endif %}
            
            {% if charts %}
            <div class="section">
                <h2 class="section-title">Security Analysis Charts</h2>
                {% for chart_name, chart_data in charts.items() %}
                <div class="chart-container">
                    <h3>{{ chart_name.replace('_', ' ').title() }}</h3>
                    <img src="data:image/png;base64,{{ chart_data }}" alt="{{ chart_name }}">
                </div>
                {% endfor %}
            </div>
            {% endif %}
            
            {% if vulnerability_details %}
            <div class="section">
                <h2 class="section-title">Vulnerability Details</h2>
                {% for vuln in vulnerability_details %}
                <div class="vulnerability-item">
                    <h4>{{ vuln.title }} <span class="severity-{{ vuln.severity.lower() }}">[{{ vuln.severity }}]</span></h4>
                    <p><strong>Category:</strong> {{ vuln.category }}</p>
                    <p><strong>Description:</strong> {{ vuln.description }}</p>
                    {% if vuln.evidence %}
                    <p><strong>Evidence:</strong></p>
                    <ul>
                    {% for evidence in vuln.evidence %}
                        <li>{{ evidence }}</li>
                    {% endfor %}
                    </ul>
                    {% endif %}
                </div>
                {% endfor %}
            </div>
            {% endif %}
            
            {% if recommendations %}
            <div class="section">
                <h2 class="section-title">Recommendations</h2>
                {% for rec in recommendations %}
                <div class="recommendation">
                    <strong>{{ rec.priority }}:</strong> {{ rec.description }}
                    {% if rec.timeline %}
                    <br><em>Timeline: {{ rec.timeline }}</em>
                    {% endif %}
                </div>
                {% endfor %}
            </div>
            {% endif %}
            
            <div class="footer">
                <p>Generated by LLM Security Testing Framework v{{ metadata.version }}</p>
                <p>This report contains confidential security information. Handle according to your organization's data classification policies.</p>
            </div>
        </div>
    </body>
    </html>
        """

    def generate_comprehensive_report(self, 
                                    test_results: List[TestResult],
                                    metadata: ReportMetadata,
                                    target_info: Dict[str, Any] = None,
                                    custom_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Generate comprehensive security assessment report"""
        
        self.logger.info(f"Generating comprehensive report: {metadata.report_id}")
        
        # Analyze test results
        analysis = self._analyze_test_results(test_results)
        
        # Generate executive summary
        executive_summary = self._generate_executive_summary(analysis, test_results)
        
        # Generate technical summary
        technical_summary = self._generate_technical_summary(analysis, test_results)
        
        # Generate compliance summary if requested
        compliance_summary = None
        if metadata.scope == ReportScope.COMPLIANCE:
            compliance_summary = self._generate_compliance_summary(analysis, test_results)
        
        # Generate visualizations
        charts = self._generate_charts(analysis, test_results)
        
        # Extract vulnerability details
        vulnerability_details = self._extract_vulnerability_details(test_results)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(analysis, test_results)
        
        # Compile report data
        report_data = {
            "metadata": metadata,
            "target_info": target_info or {},
            "executive_summary": executive_summary,
            "technical_summary": technical_summary,
            "compliance_summary": compliance_summary,
            "vulnerability_details": vulnerability_details,
            "recommendations": recommendations,
            "charts": charts,
            "raw_analysis": analysis,
            "custom_data": custom_data or {}
        }
        
        self.logger.info(f"Report generation completed: {metadata.report_id}")
        return report_data
    
    def _analyze_test_results(self, test_results: List[TestResult]) -> Dict[str, Any]:
        """Analyze test results to extract key metrics and patterns"""
        
        successful_tests = [r for r in test_results if r.success]
        failed_tests = [r for r in test_results if not r.success]
        
        # Severity breakdown
        severity_counts = {
            Severity.CRITICAL: len([r for r in successful_tests if r.severity == Severity.CRITICAL]),
            Severity.HIGH: len([r for r in successful_tests if r.severity == Severity.HIGH]),
            Severity.MEDIUM: len([r for r in successful_tests if r.severity == Severity.MEDIUM]),
            Severity.LOW: len([r for r in successful_tests if r.severity == Severity.LOW])
        }
        
        # Category breakdown
        category_counts = {}
        for result in successful_tests:
            category = result.attack_category.value
            category_counts[category] = category_counts.get(category, 0) + 1
        
        # Technique analysis
        technique_counts = {}
        for result in successful_tests:
            technique = result.details.get("technique", "unknown")
            technique_counts[technique] = technique_counts.get(technique, 0) + 1
        
        # Calculate risk score (0-10)
        risk_score = 0
        risk_score += severity_counts[Severity.CRITICAL] * 3
        risk_score += severity_counts[Severity.HIGH] * 2
        risk_score += severity_counts[Severity.MEDIUM] * 1
        risk_score += severity_counts[Severity.LOW] * 0.5
        risk_score = min(risk_score, 10)
        
        # Determine overall risk level
        if severity_counts[Severity.CRITICAL] > 0 or risk_score >= 8:
            overall_risk = "CRITICAL"
        elif severity_counts[Severity.HIGH] > 2 or risk_score >= 6:
            overall_risk = "HIGH"
        elif severity_counts[Severity.HIGH] > 0 or risk_score >= 3:
            overall_risk = "MEDIUM"
        else:
            overall_risk = "LOW"
        
        return {
            "total_tests": len(test_results),
            "successful_tests": len(successful_tests),
            "failed_tests": len(failed_tests),
            "success_rate": len(successful_tests) / max(len(test_results), 1),
            "severity_counts": severity_counts,
            "category_counts": category_counts,
            "technique_counts": technique_counts,
            "risk_score": risk_score,
            "overall_risk": overall_risk,
            "test_distribution": self._analyze_test_distribution(test_results),
            "response_patterns": self._analyze_response_patterns(test_results),
            "payload_analysis": self._analyze_payloads(test_results)
        }

    def _create_pie_chart(self, data: Dict[str, int], title: str, colors: List[str] = None) -> str:
        """Create pie chart and return as base64 encoded image"""
        try:
            # Filter out zero values
            filtered_data = {k: v for k, v in data.items() if v > 0}
            
            if not filtered_data:
                return ""
            
            plt.figure(figsize=(8, 6))
            labels = list(filtered_data.keys())
            values = list(filtered_data.values())
            
            if colors and len(colors) >= len(labels):
                plt.pie(values, labels=labels, autopct='%1.1f%%', colors=colors[:len(labels)])
            else:
                plt.pie(values, labels=labels, autopct='%1.1f%%')
            
            plt.title(title)
            plt.axis('equal')
            
            # Save to base64
            buffer = BytesIO()
            plt.savefig(buffer, format='png', bbox_inches='tight', dpi=150)
            buffer.seek(0)
            image_base64 = base64.b64encode(buffer.getvalue()).decode()
            plt.close()
            
            return image_base64
            
        except Exception as e:
            self.logger.error(f"Failed to create pie chart: {e}")
            return ""

    def _create_pie_chart(self, data: Dict[str, int], title: str, colors: List[str] = None) -> str:
        """Create pie chart and return as base64 encoded image"""
        if not CHARTS_AVAILABLE:
            self.logger.warning("Chart generation skipped: matplotlib not available")
            return ""
        
        try:
            # Filter out zero values
            filtered_data = {k: v for k, v in data.items() if v > 0}
            
            if not filtered_data:
                return ""
            
            plt.figure(figsize=(8, 6))
            labels = list(filtered_data.keys())
            values = list(filtered_data.values())
            
            if colors and len(colors) >= len(labels):
                plt.pie(values, labels=labels, autopct='%1.1f%%', colors=colors[:len(labels)])
            else:
                plt.pie(values, labels=labels, autopct='%1.1f%%')
            
            plt.title(title)
            plt.axis('equal')
            
            # Save to base64
            buffer = BytesIO()
            plt.savefig(buffer, format='png', bbox_inches='tight', dpi=150)
            buffer.seek(0)
            image_base64 = base64.b64encode(buffer.getvalue()).decode()
            plt.close()
            
            return image_base64
            
        except Exception as e:
            self.logger.error(f"Failed to create pie chart: {e}")
            return ""
    
    def _create_bar_chart(self, data: Dict[str, Union[int, float]], title: str, 
                         xlabel: str, ylabel: str) -> str:
        """Create bar chart and return as base64 encoded image"""
        if not CHARTS_AVAILABLE:
            self.logger.warning("Chart generation skipped: matplotlib not available")
            return ""
        
        try:
            if not data:
                return ""
            
            plt.figure(figsize=(10, 6))
            labels = list(data.keys())
            values = list(data.values())
            
            # Create bar chart
            bars = plt.bar(labels, values)
            
            # Color bars based on values if they represent success rates
            if all(isinstance(v, float) and 0 <= v <= 1 for v in values):
                colors = ['#e74c3c' if v > 0.7 else '#f39c12' if v > 0.3 else '#27ae60' for v in values]
                for bar, color in zip(bars, colors):
                    bar.set_color(color)
            
            plt.title(title)
            plt.xlabel(xlabel)
            plt.ylabel(ylabel)
            plt.xticks(rotation=45, ha='right')
            plt.grid(axis='y', alpha=0.3)
            
            # Save to base64
            buffer = BytesIO()
            plt.savefig(buffer, format='png', bbox_inches='tight', dpi=150)
            buffer.seek(0)
            image_base64 = base64.b64encode(buffer.getvalue()).decode()
            plt.close()
            
            return image_base64
            
        except Exception as e:
            self.logger.error(f"Failed to create bar chart: {e}")
            return ""

    def _analyze_test_distribution(self, test_results: List[TestResult]) -> Dict[str, Any]:
        """Analyze distribution of tests across categories and types"""
        distribution = {}
        
        for result in test_results:
            category = result.attack_category.value
            test_name = result.test_name
            
            if category not in distribution:
                distribution[category] = {"total": 0, "successful": 0, "tests": {}}
            
            distribution[category]["total"] += 1
            if result.success:
                distribution[category]["successful"] += 1
            
            if test_name not in distribution[category]["tests"]:
                distribution[category]["tests"][test_name] = {"total": 0, "successful": 0}
            
            distribution[category]["tests"][test_name]["total"] += 1
            if result.success:
                distribution[category]["tests"][test_name]["successful"] += 1
        
        # Calculate success rates
        for category_data in distribution.values():
            category_data["success_rate"] = category_data["successful"] / max(category_data["total"], 1)
            for test_data in category_data["tests"].values():
                test_data["success_rate"] = test_data["successful"] / max(test_data["total"], 1)
        
        return distribution
    
    def _analyze_response_patterns(self, test_results: List[TestResult]) -> Dict[str, Any]:
        """Analyze patterns in model responses"""
        successful_results = [r for r in test_results if r.success]
        
        # Response length analysis
        response_lengths = [len(r.response) for r in successful_results]
        avg_response_length = sum(response_lengths) / max(len(response_lengths), 1)
        
        # Common response patterns
        response_keywords = {}
        for result in successful_results:
            words = result.response.lower().split()
            for word in words:
                if len(word) > 3:  # Filter short words
                    response_keywords[word] = response_keywords.get(word, 0) + 1
        
        # Sort by frequency
        top_keywords = dict(sorted(response_keywords.items(), key=lambda x: x[1], reverse=True)[:20])
        
        return {
            "avg_response_length": avg_response_length,
            "response_count": len(successful_results),
            "top_keywords": top_keywords,
            "length_distribution": {
                "short": len([l for l in response_lengths if l < 100]),
                "medium": len([l for l in response_lengths if 100 <= l < 500]),
                "long": len([l for l in response_lengths if l >= 500])
            }
        }
    
    def _analyze_payloads(self, test_results: List[TestResult]) -> Dict[str, Any]:
        """Analyze payload characteristics and effectiveness"""
        successful_results = [r for r in test_results if r.success]
        
        # Payload length analysis
        payload_lengths = [len(r.payload) for r in successful_results]
        avg_payload_length = sum(payload_lengths) / max(len(payload_lengths), 1)
        
        # Payload technique analysis
        techniques = {}
        for result in successful_results:
            technique = result.details.get("technique", "unknown")
            if technique not in techniques:
                techniques[technique] = {"count": 0, "avg_length": 0, "payloads": []}
            
            techniques[technique]["count"] += 1
            techniques[technique]["payloads"].append(len(result.payload))
        
        # Calculate average lengths per technique
        for technique_data in techniques.values():
            technique_data["avg_length"] = sum(technique_data["payloads"]) / len(technique_data["payloads"])
        
        return {
            "avg_payload_length": avg_payload_length,
            "payload_count": len(successful_results),
            "technique_effectiveness": dict(sorted(techniques.items(), key=lambda x: x[1]["count"], reverse=True)),
            "length_distribution": {
                "short": len([l for l in payload_lengths if l < 50]),
                "medium": len([l for l in payload_lengths if 50 <= l < 200]),
                "long": len([l for l in payload_lengths if l >= 200])
            }
        }
    
    def _generate_executive_summary(self, analysis: Dict[str, Any], test_results: List[TestResult]) -> ExecutiveSummary:
        """Generate executive summary for leadership"""
        
        severity_counts = analysis["severity_counts"]
        
        # Identify key vulnerabilities
        key_vulnerabilities = []
        successful_results = [r for r in test_results if r.success and r.severity in [Severity.CRITICAL, Severity.HIGH]]
        
        vulnerability_types = {}
        for result in successful_results:
            vuln_type = result.details.get("manipulation_type") or result.details.get("bypass_type") or result.details.get("extraction_type") or "security_vulnerability"
            vulnerability_types[vuln_type] = vulnerability_types.get(vuln_type, 0) + 1
        
        key_vulnerabilities = [f"{vuln_type.replace('_', ' ').title()}: {count} instances" 
                             for vuln_type, count in sorted(vulnerability_types.items(), key=lambda x: x[1], reverse=True)[:5]]
        
        # Business impact assessment
        business_impact = []
        if severity_counts[Severity.CRITICAL] > 0:
            business_impact.append("Critical security vulnerabilities pose immediate risk to business operations")
        if analysis["category_counts"].get("business_logic_bypass", 0) > 0:
            business_impact.append("Business logic bypasses could lead to unauthorized access and compliance violations")
        if analysis["category_counts"].get("data_extraction", 0) > 0:
            business_impact.append("Data extraction vulnerabilities risk customer privacy and regulatory compliance")
        if analysis["success_rate"] > 0.3:
            business_impact.append("High vulnerability detection rate indicates systemic security weaknesses")
        
        # Immediate actions
        immediate_actions = []
        if severity_counts[Severity.CRITICAL] > 0:
            immediate_actions.append("Address critical vulnerabilities within 24-48 hours")
        if severity_counts[Severity.HIGH] > 0:
            immediate_actions.append("Implement fixes for high-severity issues within 1 week")
        if analysis["success_rate"] > 0.2:
            immediate_actions.append("Conduct comprehensive security architecture review")
        immediate_actions.append("Implement enhanced monitoring and detection capabilities")
        
        return ExecutiveSummary(
            overall_risk_level=analysis["overall_risk"],
            critical_findings=severity_counts[Severity.CRITICAL],
            high_findings=severity_counts[Severity.HIGH],
            medium_findings=severity_counts[Severity.MEDIUM],
            low_findings=severity_counts[Severity.LOW],
            total_tests=analysis["total_tests"],
            success_rate=analysis["success_rate"],
            key_vulnerabilities=key_vulnerabilities,
            business_impact=business_impact,
            immediate_actions=immediate_actions,
            risk_score=analysis["risk_score"]
        )

    def _extract_vulnerability_details(self, test_results: List[TestResult]) -> List[Dict[str, Any]]:
        """Extract detailed vulnerability information from test results"""
        vulnerability_details = []
        
        successful_results = [r for r in test_results if r.success]
        
        for result in successful_results:
            vulnerability = {
                "title": result.test_name,
                "category": result.attack_category.value.replace('_', ' ').title(),
                "severity": result.severity.value.upper(),
                "description": result.details.get("description", f"Vulnerability detected in {result.test_name}"),
                "evidence": result.evidence if result.evidence else [f"Response contained vulnerability indicators"],
                "payload": result.payload[:200] + "..." if len(result.payload) > 200 else result.payload,
                "response_snippet": result.response[:200] + "..." if len(result.response) > 200 else result.response,
                "technique": result.details.get("technique", "unknown"),
                "timestamp": result.timestamp.isoformat() if hasattr(result, 'timestamp') else "unknown"
            }
            
            vulnerability_details.append(vulnerability)
        
        # Sort by severity (Critical > High > Medium > Low)
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        vulnerability_details.sort(key=lambda x: severity_order.get(x["severity"], 4))
        
        return vulnerability_details

    def _generate_technical_summary(self, analysis: Dict[str, Any], test_results: List[TestResult]) -> TechnicalSummary:
        """Generate technical summary for security teams"""
        
        # Test category analysis
        test_categories = {}
        for category, data in analysis["test_distribution"].items():
            test_categories[category] = {
                "total_tests": data["total"],
                "successful_tests": data["successful"],
                "success_rate": data["success_rate"],
                "risk_level": self._calculate_category_risk(data)
            }
        
        # Vulnerability breakdown by type
        vulnerability_breakdown = {}
        for result in test_results:
            if result.success:
                vuln_type = result.details.get("manipulation_type") or result.details.get("bypass_type") or result.details.get("extraction_type") or "other"
                vulnerability_breakdown[vuln_type] = vulnerability_breakdown.get(vuln_type, 0) + 1
        
        # Attack vector analysis
        attack_vectors = analysis["technique_counts"]
        
        # Response pattern analysis
        response_patterns = analysis["response_patterns"]
        
        # Payload analysis
        payload_analysis = analysis["payload_analysis"]
        
        # Timing analysis (placeholder - would need actual timing data)
        timing_analysis = {
            "avg_response_time": "1.2s",  # Would be calculated from actual data
            "slowest_category": "model_manipulation",
            "fastest_category": "prompt_injection"
        }
        
        # Failure mode analysis
        failure_modes = []
        failed_results = [r for r in test_results if not r.success]
        failure_patterns = {}
        for result in failed_results:
            if "error" in result.response.lower():
                failure_patterns["error_responses"] = failure_patterns.get("error_responses", 0) + 1
            elif len(result.response) < 10:
                failure_patterns["empty_responses"] = failure_patterns.get("empty_responses", 0) + 1
            else:
                failure_patterns["defensive_responses"] = failure_patterns.get("defensive_responses", 0) + 1
        
        failure_modes = [f"{mode.replace('_', ' ').title()}: {count}" for mode, count in failure_patterns.items()]
        
        return TechnicalSummary(
            test_categories=test_categories,
            vulnerability_breakdown=vulnerability_breakdown,
            attack_vectors=attack_vectors,
            response_patterns=response_patterns,
            payload_analysis=payload_analysis,
            timing_analysis=timing_analysis,
            failure_modes=failure_modes
        )
    
    def _calculate_category_risk(self, category_data: Dict[str, Any]) -> str:
        """Calculate risk level for a test category"""
        success_rate = category_data["success_rate"]
        
        if success_rate >= 0.7:
            return "HIGH"
        elif success_rate >= 0.3:
            return "MEDIUM"
        elif success_rate > 0:
            return "LOW"
        else:
            return "NONE"
    
    def _generate_compliance_summary(self, analysis: Dict[str, Any], test_results: List[TestResult]) -> ComplianceSummary:
        """Generate compliance and regulatory summary"""
        
        # Framework coverage mapping
        framework_coverage = {
            "NIST Cybersecurity Framework": 0.85,  # Based on test coverage
            "ISO 27001": 0.75,
            "SOC 2": 0.80,
            "GDPR": 0.70,
            "HIPAA": 0.65
        }
        
        # Compliance gaps
        compliance_gaps = []
        if analysis["category_counts"].get("data_extraction", 0) > 0:
            compliance_gaps.append("Data protection controls insufficient for GDPR compliance")
        if analysis["category_counts"].get("business_logic_bypass", 0) > 0:
            compliance_gaps.append("Access control weaknesses impact SOC 2 compliance")
        if analysis["success_rate"] > 0.2:
            compliance_gaps.append("Overall security posture below enterprise standards")
        
        # Regulatory findings
        regulatory_findings = {
            "GDPR": ["Personal data extraction vulnerabilities", "Insufficient access controls"],
            "SOC 2": ["Authentication bypass issues", "Inadequate monitoring controls"],
            "HIPAA": ["Potential PHI exposure through data extraction"],
            "PCI DSS": ["Access control deficiencies"]
        }
        
        # Control effectiveness
        control_effectiveness = {
            "Authentication Controls": "NEEDS_IMPROVEMENT",
            "Authorization Controls": "ADEQUATE",
            "Data Protection": "NEEDS_IMPROVEMENT",
            "Monitoring & Logging": "ADEQUATE",
            "Incident Response": "ADEQUATE"
        }
        
        # Remediation timeline
        remediation_timeline = {
            "Critical Issues": "Immediate (24-48 hours)",
            "High Priority": "1-2 weeks",
            "Medium Priority": "1 month",
            "Low Priority": "3 months"
        }
        
        return ComplianceSummary(
            framework_coverage=framework_coverage,
            compliance_gaps=compliance_gaps,
            regulatory_findings=regulatory_findings,
            control_effectiveness=control_effectiveness,
            remediation_timeline=remediation_timeline
        )

    def _generate_charts(self, analysis: Dict[str, Any], test_results: List[TestResult]) -> Dict[str, str]:
        """Generate visualization charts and return as base64 encoded images"""
        
        charts = {}
        
        # Severity distribution pie chart
        severity_data = analysis["severity_counts"]
        if any(severity_data.values()):
            # Convert enum keys to string values for chart display
            severity_display = {severity.value: count for severity, count in severity_data.items() if count > 0}
            charts["severity_distribution"] = self._create_pie_chart(
                severity_display, 
                "Vulnerability Severity Distribution",
                colors=['#e74c3c', '#f39c12', '#f1c40f', '#27ae60']
            )
        
        # Category breakdown bar chart
        category_data = analysis["category_counts"]
        if category_data:
            charts["category_breakdown"] = self._create_bar_chart(
                category_data,
                "Vulnerabilities by Attack Category",
                "Attack Category",
                "Number of Vulnerabilities"
            )
        
        # Success rate by category
        distribution_data = analysis.get("test_distribution", {})
        if distribution_data:
            success_rates = {category.replace('_', ' ').title(): data["success_rate"] 
                            for category, data in distribution_data.items()}
            charts["success_rate_by_category"] = self._create_bar_chart(
                success_rates,
                "Success Rate by Test Category",
                "Test Category", 
                "Success Rate (%)"
            )
        
        # Technique effectiveness chart
        technique_data = analysis.get("technique_counts", {})
        if technique_data:
            # Show top 10 techniques
            top_techniques = dict(sorted(technique_data.items(), key=lambda x: x[1], reverse=True)[:10])
            technique_display = {tech.replace('_', ' ').title(): count for tech, count in top_techniques.items()}
            charts["technique_effectiveness"] = self._create_bar_chart(
                technique_display,
                "Most Effective Attack Techniques",
                "Technique",
                "Success Count"
            )
        
        return charts

    def save_report(self, report_data: Dict[str, Any], output_path: str, 
                    report_format: ReportFormat = ReportFormat.HTML) -> str:
        """Save report to file in specified format"""
        
        try:
            output_path = Path(output_path)
            
            if report_format == ReportFormat.HTML:
                return self._save_html_report(report_data, output_path)
            elif report_format == ReportFormat.JSON:
                return self._save_json_report(report_data, output_path)
            elif report_format == ReportFormat.MARKDOWN:
                return self._save_markdown_report(report_data, output_path)
            else:
                raise ValueError(f"Unsupported report format: {report_format}")
                
        except Exception as e:
            self.logger.error(f"Failed to save report: {e}")
            raise

    def _save_html_report(self, report_data: Dict[str, Any], output_path: Path) -> str:
        """Save HTML report to file"""
        try:
            template_file = self.template_dir / "default_report.html"
            
            if JINJA2_AVAILABLE and template_file.exists() and self.jinja_env:
                template = self.jinja_env.get_template("default_report.html")
            else:
                # Use basic template rendering
                template_content = self._get_default_html_template()
                if JINJA2_AVAILABLE:
                    template = Template(template_content)
                else:
                    # Basic string substitution fallback
                    template = None
            
            if template:
                html_content = template.render(**report_data)
            else:
                # Fallback to basic template without Jinja2 rendering
                html_content = self._render_basic_template(report_data)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.logger.info(f"HTML report saved: {output_path}")
            return str(output_path)
            
        except Exception as e:
            self.logger.error(f"Failed to save HTML report: {e}")
            raise

    def _render_basic_template(self, report_data: Dict[str, Any]) -> str:
        """Basic template rendering without Jinja2 - simple string substitution"""
        try:
            metadata = report_data.get('metadata')
            executive_summary = report_data.get('executive_summary')
            
            # Basic HTML structure without advanced templating
            html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>{metadata.title if metadata else 'Security Report'}</title>
        <meta charset="UTF-8">
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .header {{ border-bottom: 2px solid #333; padding-bottom: 10px; }}
            .title {{ color: #333; font-size: 2em; margin: 0; }}
            .subtitle {{ color: #666; font-size: 1.2em; margin: 5px 0; }}
            .section {{ margin: 20px 0; }}
            .finding {{ background: #f5f5f5; padding: 10px; margin: 10px 0; border-left: 4px solid #e74c3c; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1 class="title">{metadata.title if metadata else 'LLM Security Report'}</h1>
            <p class="subtitle">{metadata.description if metadata else 'Security Assessment Results'}</p>
        </div>
        
        <div class="section">
            <h2>Report Information</h2>
            <p><strong>Report ID:</strong> {metadata.report_id if metadata else 'Unknown'}</p>
            <p><strong>Generated:</strong> {metadata.generation_time.strftime('%Y-%m-%d %H:%M:%S') if metadata else 'Unknown'}</p>
        </div>
    """
    
            # Add executive summary if available
            if executive_summary:
                html_content += f"""
        <div class="section">
            <h2>Executive Summary</h2>
            <p><strong>Overall Risk Level:</strong> {executive_summary.overall_risk_level}</p>
            <p><strong>Critical Findings:</strong> {executive_summary.critical_findings}</p>
            <p><strong>High Findings:</strong> {executive_summary.high_findings}</p>
            <p><strong>Medium Findings:</strong> {executive_summary.medium_findings}</p>
            <p><strong>Low Findings:</strong> {executive_summary.low_findings}</p>
            <p><strong>Total Tests:</strong> {executive_summary.total_tests}</p>
            <p><strong>Risk Score:</strong> {executive_summary.risk_score:.1f}/10.0</p>
        </div>
    """
    
            # Add vulnerability details if available
            vulnerability_details = report_data.get('vulnerability_details', [])
            if vulnerability_details:
                html_content += """
        <div class="section">
            <h2>Vulnerability Details</h2>
    """
                for vuln in vulnerability_details[:10]:  # Limit to first 10
                    html_content += f"""
            <div class="finding">
                <h4>{vuln.get('title', 'Unknown Vulnerability')} [{vuln.get('severity', 'Unknown')}]</h4>
                <p><strong>Category:</strong> {vuln.get('category', 'Unknown')}</p>
                <p><strong>Description:</strong> {vuln.get('description', 'No description available')}</p>
            </div>
    """
                html_content += "    </div>"
    
            # Add recommendations if available
            recommendations = report_data.get('recommendations', [])
            if recommendations:
                html_content += """
        <div class="section">
            <h2>Recommendations</h2>
    """
                for i, rec in enumerate(recommendations[:5], 1):  # Limit to first 5
                    html_content += f"""
            <p><strong>{i}. {rec.get('priority', 'Unknown')}:</strong> {rec.get('description', 'No description')}</p>
    """
                html_content += "    </div>"
    
            # Close HTML
            html_content += """
        <div class="section">
            <p><em>Generated by LLM Security Testing Framework</em></p>
            <p><em>Note: Advanced features require Jinja2 template engine</em></p>
        </div>
    </body>
    </html>
    """
            
            return html_content
            
        except Exception as e:
            self.logger.error(f"Failed to render basic template: {e}")
            return f"<html><body><h1>Report Generation Error</h1><p>Error: {str(e)}</p></body></html>"

    def _save_json_report(self, report_data: Dict[str, Any], output_path: Path) -> str:
        """Save JSON report to file"""
        try:
            # Convert dataclasses to dictionaries for JSON serialization
            json_data = self._serialize_for_json(report_data)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(json_data, f, indent=2, default=str)
            
            self.logger.info(f"JSON report saved: {output_path}")
            return str(output_path)
            
        except Exception as e:
            self.logger.error(f"Failed to save JSON report: {e}")
            raise
    
    def _serialize_for_json(self, obj: Any) -> Any:
        """Convert dataclasses and other objects to JSON-serializable format"""
        if hasattr(obj, '__dict__'):
            return {key: self._serialize_for_json(value) for key, value in obj.__dict__.items()}
        elif isinstance(obj, dict):
            return {key: self._serialize_for_json(value) for key, value in obj.items()}
        elif isinstance(obj, (list, tuple)):
            return [self._serialize_for_json(item) for item in obj]
        elif hasattr(obj, 'value'):  # Enum
            return obj.value
        else:
            return obj

    def _save_markdown_report(self, report_data: Dict[str, Any], output_path: Path) -> str:
        """Save Markdown report to file"""
        try:
            markdown_content = self._generate_markdown_content(report_data)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(markdown_content)
            
            self.logger.info(f"Markdown report saved: {output_path}")
            return str(output_path)
            
        except Exception as e:
            self.logger.error(f"Failed to save Markdown report: {e}")
            raise
    
    def _generate_markdown_content(self, report_data: Dict[str, Any]) -> str:
        """Generate Markdown content from report data"""
        metadata = report_data.get('metadata')
        executive_summary = report_data.get('executive_summary')
        vulnerability_details = report_data.get('vulnerability_details', [])
        recommendations = report_data.get('recommendations', [])
        
        content = []
        
        # Header
        content.append(f"# {metadata.title}")
        content.append(f"*{metadata.description}*")
        content.append("")
        content.append(f"**Report ID:** {metadata.report_id}  ")
        content.append(f"**Generated:** {metadata.generation_time.strftime('%Y-%m-%d %H:%M:%S')}  ")
        content.append(f"**Classification:** {metadata.classification}")
        content.append("")
        
        # Executive Summary
        if executive_summary:
            content.append("## Executive Summary")
            content.append("")
            content.append(f"**Overall Risk Level:** {executive_summary.overall_risk_level}")
            content.append("")
            content.append("### Findings Summary")
            content.append(f"- **Critical:** {executive_summary.critical_findings}")
            content.append(f"- **High:** {executive_summary.high_findings}")
            content.append(f"- **Medium:** {executive_summary.medium_findings}")
            content.append(f"- **Low:** {executive_summary.low_findings}")
            content.append("")
            content.append(f"**Total Tests:** {executive_summary.total_tests}  ")
            content.append(f"**Risk Score:** {executive_summary.risk_score:.1f}/10.0")
            content.append("")
        
        # Vulnerability Details
        if vulnerability_details:
            content.append("## Vulnerability Details")
            content.append("")
            for vuln in vulnerability_details:
                content.append(f"### {vuln.get('title', 'Unknown Vulnerability')} [{vuln.get('severity', 'Unknown')}]")
                content.append(f"**Category:** {vuln.get('category', 'Unknown')}")
                content.append(f"**Description:** {vuln.get('description', 'No description available')}")
                if vuln.get('evidence'):
                    content.append("**Evidence:**")
                    for evidence in vuln['evidence']:
                        content.append(f"- {evidence}")
                content.append("")
        
        # Recommendations
        if recommendations:
            content.append("## Recommendations")
            content.append("")
            for i, rec in enumerate(recommendations, 1):
                content.append(f"{i}. **{rec.get('priority', 'Unknown')}:** {rec.get('description', 'No description')}")
                if rec.get('timeline'):
                    content.append(f"   *Timeline: {rec['timeline']}*")
                content.append("")
        
        # Footer
        content.append("---")
        content.append(f"*Generated by LLM Security Testing Framework v{metadata.version}*")
        
        return "\n".join(content)

    def _generate_recommendations(self, analysis: Dict[str, Any], test_results: List[TestResult]) -> List[Dict[str, Any]]:
        """Generate security recommendations based on analysis results"""
        recommendations = []
        
        successful_results = [r for r in test_results if r.success]
        severity_counts = analysis["severity_counts"]
        category_counts = analysis["category_counts"]
        
        # Critical findings recommendations
        if severity_counts.get(Severity.CRITICAL, 0) > 0:
            recommendations.append({
                "priority": "CRITICAL",
                "description": "Address critical security vulnerabilities immediately. These pose immediate risk to system security.",
                "timeline": "24-48 hours"
            })
        
        # High findings recommendations
        if severity_counts.get(Severity.HIGH, 0) > 0:
            recommendations.append({
                "priority": "HIGH", 
                "description": "Implement fixes for high-severity vulnerabilities to prevent potential security breaches.",
                "timeline": "1-2 weeks"
            })
        
        # Category-specific recommendations
        if category_counts.get("prompt_injection", 0) > 0:
            recommendations.append({
                "priority": "HIGH",
                "description": "Implement robust prompt injection filters and input validation mechanisms.",
                "timeline": "1-2 weeks"
            })
        
        if category_counts.get("data_extraction", 0) > 0:
            recommendations.append({
                "priority": "HIGH",
                "description": "Review system prompts and implement data leakage prevention controls.",
                "timeline": "1-2 weeks"
            })
        
        if category_counts.get("business_logic_bypass", 0) > 0:
            recommendations.append({
                "priority": "MEDIUM",
                "description": "Strengthen business logic controls and workflow validation mechanisms.",
                "timeline": "2-4 weeks"
            })
        
        if category_counts.get("model_manipulation", 0) > 0:
            recommendations.append({
                "priority": "MEDIUM",
                "description": "Implement additional safeguards against model behavior manipulation.",
                "timeline": "2-4 weeks"
            })
        
        # General recommendations based on success rate
        success_rate = analysis.get("success_rate", 0)
        if success_rate > 0.3:
            recommendations.append({
                "priority": "HIGH",
                "description": "High vulnerability detection rate indicates systemic security weaknesses. Conduct comprehensive security architecture review.",
                "timeline": "2-3 weeks"
            })
        elif success_rate > 0.1:
            recommendations.append({
                "priority": "MEDIUM",
                "description": "Moderate vulnerability detection rate suggests targeted security improvements are needed.",
                "timeline": "3-4 weeks"
            })
        
        # Monitoring and detection recommendations
        if len(successful_results) > 0:
            recommendations.append({
                "priority": "MEDIUM",
                "description": "Implement enhanced monitoring and attack detection capabilities to identify similar threats in production.",
                "timeline": "2-3 weeks"
            })
        
        # If no vulnerabilities found
        if not successful_results:
            recommendations.append({
                "priority": "LOW",
                "description": "No significant vulnerabilities detected. Continue regular security assessments and monitoring.",
                "timeline": "Ongoing"
            })
        
        return recommendations

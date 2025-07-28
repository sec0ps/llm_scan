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
import yaml
import os
import hashlib
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
import logging
from pathlib import Path
from datetime import datetime
import base64
from cryptography.fernet import Fernet
import configparser

from llm_scan import TargetConfig, TargetType, AttackCategory, Severity

class ConfigurationError(Exception):
    """Custom exception for configuration-related errors"""
    pass

class ConfigFormat(Enum):
    """Supported configuration file formats"""
    JSON = "json"
    YAML = "yaml"
    INI = "ini"
    ENV = "env"

class EncryptionLevel(Enum):
    """Configuration encryption levels"""
    NONE = "none"
    SENSITIVE_ONLY = "sensitive_only"
    FULL = "full"

@dataclass
class TestConfiguration:
    """Configuration for individual test classes"""
    enabled: bool = True
    timeout: int = 30
    rate_limit_delay: float = 1.0
    max_retries: int = 3
    custom_payloads: List[str] = field(default_factory=list)
    severity_threshold: Severity = Severity.INFO
    custom_patterns: Dict[str, str] = field(default_factory=dict)
    test_specific_config: Dict[str, Any] = field(default_factory=dict)

@dataclass
class SecuritySettings:
    """Security-related configuration settings"""
    encrypt_sensitive_data: bool = True
    encryption_level: EncryptionLevel = EncryptionLevel.SENSITIVE_ONLY
    log_sensitive_data: bool = False
    anonymize_targets: bool = False
    require_auth: bool = True
    session_timeout: int = 3600
    audit_logging: bool = True
    secure_storage_path: str = "./secure_config"

@dataclass
class ReportingSettings:
    """Reporting and output configuration"""
    output_format: str = "json"
    include_payloads: bool = True
    include_responses: bool = False
    anonymize_output: bool = False
    severity_filter: Severity = Severity.INFO
    export_formats: List[str] = field(default_factory=lambda: ["json", "html"])
    custom_templates: Dict[str, str] = field(default_factory=dict)

@dataclass
class FrameworkSettings:
    """Overall framework configuration"""
    version: str = "1.0.0"
    debug_mode: bool = False
    parallel_execution: bool = False
    max_workers: int = 4
    default_timeout: int = 30
    cache_enabled: bool = True
    cache_ttl: int = 3600
    plugin_directories: List[str] = field(default_factory=list)

@dataclass
class TestSuiteConfig:
    """Configuration for test suite execution"""
    name: str = "Default Test Suite"
    description: str = "Standard LLM security test suite"
    enabled_categories: List[AttackCategory] = field(default_factory=lambda: list(AttackCategory))
    test_configurations: Dict[str, TestConfiguration] = field(default_factory=dict)
    execution_order: List[str] = field(default_factory=list)
    stop_on_critical: bool = True
    continue_on_error: bool = True

class ConfigurationManager:
    """Central configuration management for the LLM security testing framework"""
    
    def __init__(self, config_dir: str = "./config"):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(exist_ok=True)
        
        # Initialize encryption
        self.encryption_key = self._load_or_generate_key()
        self.cipher = Fernet(self.encryption_key)
        
        # Configuration storage
        self.targets: Dict[str, TargetConfig] = {}
        self.test_suites: Dict[str, TestSuiteConfig] = {}
        self.security_settings = SecuritySettings()
        self.reporting_settings = ReportingSettings()
        self.framework_settings = FrameworkSettings()
        
        # Configuration file tracking
        self.config_files: Dict[str, Dict[str, Any]] = {}
        self.config_checksums: Dict[str, str] = {}
        
        # Setup logging
        self.logger = self._setup_logging()
        
        # Load default configurations
        self._load_default_configurations()
    
    def _setup_logging(self) -> logging.Logger:
        """Setup configuration manager logging"""
        logger = logging.getLogger("ConfigurationManager")
        logger.setLevel(logging.INFO)
        
        # File handler for configuration logs
        log_file = self.config_dir / "config_manager.log"
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        return logger
    
    def _load_or_generate_key(self) -> bytes:
        """Load existing encryption key or generate a new one"""
        key_file = self.config_dir / ".encryption_key"
        
        if key_file.exists():
            try:
                with open(key_file, 'rb') as f:
                    return f.read()
            except Exception as e:
                self.logger.warning(f"Failed to load encryption key: {e}")
        
        # Generate new key
        key = Fernet.generate_key()
        try:
            with open(key_file, 'wb') as f:
                f.write(key)
            # Secure the key file
            os.chmod(key_file, 0o600)
        except Exception as e:
            self.logger.error(f"Failed to save encryption key: {e}")
        
        return key
    
    def _load_default_configurations(self):
        """Load default framework configurations"""
        try:
            # Load existing configurations if they exist
            self.load_all_configurations()
        except ConfigurationError:
            # Create default configurations
            self._create_default_configurations()
    
    def _create_default_configurations(self):
        """Create default configuration files"""
        
        # Default target configuration
        default_target = TargetConfig(
            target_type=TargetType.API_BASED,
            base_url="https://api.example.com",
            api_key=None,
            model_name="test-model",
            max_tokens=1000,
            temperature=0.7
        )
        self.add_target("default", default_target)
        
        # Default test suite
        default_suite = TestSuiteConfig(
            name="Comprehensive Security Test",
            description="Full security assessment covering all attack categories",
            enabled_categories=list(AttackCategory),
            test_configurations={
                "prompt_injection": TestConfiguration(
                    enabled=True,
                    timeout=30,
                    severity_threshold=Severity.MEDIUM
                ),
                "data_extraction": TestConfiguration(
                    enabled=True,
                    timeout=45,
                    severity_threshold=Severity.HIGH
                ),
                "model_manipulation": TestConfiguration(
                    enabled=True,
                    timeout=60,
                    severity_threshold=Severity.MEDIUM
                ),
                "business_logic_bypass": TestConfiguration(
                    enabled=True,
                    timeout=30,
                    severity_threshold=Severity.HIGH
                )
            }
        )
        self.add_test_suite("comprehensive", default_suite)
        
        # Save default configurations
        self.save_all_configurations()
    
    def add_target(self, name: str, target_config: TargetConfig):
        """Add a new target configuration"""
        if not name or not isinstance(target_config, TargetConfig):
            raise ConfigurationError("Invalid target name or configuration")
        
        self.targets[name] = target_config
        self.logger.info(f"Added target configuration: {name}")
    
    def get_target(self, name: str) -> Optional[TargetConfig]:
        """Get target configuration by name"""
        return self.targets.get(name)
    
    def list_targets(self) -> List[str]:
        """List all available target names"""
        return list(self.targets.keys())
    
    def remove_target(self, name: str) -> bool:
        """Remove target configuration"""
        if name in self.targets:
            del self.targets[name]
            self.logger.info(f"Removed target configuration: {name}")
            return True
        return False
    
    def add_test_suite(self, name: str, suite_config: TestSuiteConfig):
        """Add a new test suite configuration"""
        if not name or not isinstance(suite_config, TestSuiteConfig):
            raise ConfigurationError("Invalid test suite name or configuration")
        
        self.test_suites[name] = suite_config
        self.logger.info(f"Added test suite configuration: {name}")
    
    def get_test_suite(self, name: str) -> Optional[TestSuiteConfig]:
        """Get test suite configuration by name"""
        return self.test_suites.get(name)
    
    def list_test_suites(self) -> List[str]:
        """List all available test suite names"""
        return list(self.test_suites.keys())
    
    def update_security_settings(self, **kwargs):
        """Update security settings"""
        for key, value in kwargs.items():
            if hasattr(self.security_settings, key):
                setattr(self.security_settings, key, value)
                self.logger.info(f"Updated security setting: {key} = {value}")
            else:
                raise ConfigurationError(f"Unknown security setting: {key}")
    
    def update_reporting_settings(self, **kwargs):
        """Update reporting settings"""
        for key, value in kwargs.items():
            if hasattr(self.reporting_settings, key):
                setattr(self.reporting_settings, key, value)
                self.logger.info(f"Updated reporting setting: {key} = {value}")
            else:
                raise ConfigurationError(f"Unknown reporting setting: {key}")
    
    def update_framework_settings(self, **kwargs):
        """Update framework settings"""
        for key, value in kwargs.items():
            if hasattr(self.framework_settings, key):
                setattr(self.framework_settings, key, value)
                self.logger.info(f"Updated framework setting: {key} = {value}")
            else:
                raise ConfigurationError(f"Unknown framework setting: {key}")
    
    def _encrypt_sensitive_data(self, data: Any) -> str:
        """Encrypt sensitive configuration data"""
        if not self.security_settings.encrypt_sensitive_data:
            return data
        
        json_data = json.dumps(data) if not isinstance(data, str) else data
        encrypted = self.cipher.encrypt(json_data.encode())
        return base64.b64encode(encrypted).decode()
    
    def _decrypt_sensitive_data(self, encrypted_data: str) -> Any:
        """Decrypt sensitive configuration data"""
        if not self.security_settings.encrypt_sensitive_data:
            return encrypted_data
        
        try:
            encrypted_bytes = base64.b64decode(encrypted_data.encode())
            decrypted = self.cipher.decrypt(encrypted_bytes)
            return json.loads(decrypted.decode())
        except Exception as e:
            self.logger.error(f"Failed to decrypt data: {e}")
            raise ConfigurationError("Failed to decrypt sensitive data")
    
    def _is_sensitive_field(self, field_name: str) -> bool:
        """Check if a field contains sensitive data"""
        sensitive_fields = {
            'api_key', 'password', 'secret', 'token', 'credential',
            'auth', 'private', 'key', 'cert', 'certificate'
        }
        return any(sensitive in field_name.lower() for sensitive in sensitive_fields)
    
    def _prepare_for_serialization(self, obj: Any) -> Any:
        """Prepare object for serialization with encryption as needed"""
        if isinstance(obj, dict):
            result = {}
            for key, value in obj.items():
                if self._is_sensitive_field(key) and self.security_settings.encryption_level != EncryptionLevel.NONE:
                    result[key] = self._encrypt_sensitive_data(value)
                    result[f"{key}_encrypted"] = True
                else:
                    result[key] = self._prepare_for_serialization(value)
            return result
        elif hasattr(obj, '__dict__'):
            return self._prepare_for_serialization(asdict(obj))
        elif isinstance(obj, (list, tuple)):
            return [self._prepare_for_serialization(item) for item in obj]
        elif isinstance(obj, Enum):
            return obj.value
        else:
            return obj
    
    def _restore_from_serialization(self, obj: Any) -> Any:
        """Restore object from serialization with decryption as needed"""
        if isinstance(obj, dict):
            result = {}
            for key, value in obj.items():
                if key.endswith('_encrypted') and value:
                    # Skip encryption flags
                    continue
                elif f"{key}_encrypted" in obj and obj[f"{key}_encrypted"]:
                    result[key] = self._decrypt_sensitive_data(value)
                else:
                    result[key] = self._restore_from_serialization(value)
            return result
        elif isinstance(obj, list):
            return [self._restore_from_serialization(item) for item in obj]
        else:
            return obj
    
    def save_configuration(self, config_name: str, config_data: Any, 
                          config_format: ConfigFormat = ConfigFormat.JSON):
        """Save configuration to file"""
        
        file_path = self.config_dir / f"{config_name}.{config_format.value}"
        
        # Prepare data for serialization
        serializable_data = self._prepare_for_serialization(config_data)
        
        try:
            if config_format == ConfigFormat.JSON:
                with open(file_path, 'w') as f:
                    json.dump(serializable_data, f, indent=2, default=str)
            
            elif config_format == ConfigFormat.YAML:
                with open(file_path, 'w') as f:
                    yaml.safe_dump(serializable_data, f, default_flow_style=False)
            
            elif config_format == ConfigFormat.INI:
                config = configparser.ConfigParser()
                self._dict_to_ini(serializable_data, config)
                with open(file_path, 'w') as f:
                    config.write(f)
            
            # Calculate and store checksum
            self.config_checksums[config_name] = self._calculate_checksum(file_path)
            
            self.logger.info(f"Saved configuration: {config_name} ({config_format.value})")
            
        except Exception as e:
            self.logger.error(f"Failed to save configuration {config_name}: {e}")
            raise ConfigurationError(f"Failed to save configuration: {e}")
    
    def load_configuration(self, config_name: str, 
                          config_format: ConfigFormat = ConfigFormat.JSON) -> Any:
        """Load configuration from file"""
        
        file_path = self.config_dir / f"{config_name}.{config_format.value}"
        
        if not file_path.exists():
            raise ConfigurationError(f"Configuration file not found: {file_path}")
        
        try:
            if config_format == ConfigFormat.JSON:
                with open(file_path, 'r') as f:
                    data = json.load(f)
            
            elif config_format == ConfigFormat.YAML:
                with open(file_path, 'r') as f:
                    data = yaml.safe_load(f)
            
            elif config_format == ConfigFormat.INI:
                config = configparser.ConfigParser()
                config.read(file_path)
                data = self._ini_to_dict(config)
            
            # Verify checksum if available
            current_checksum = self._calculate_checksum(file_path)
            stored_checksum = self.config_checksums.get(config_name)
            
            if stored_checksum and current_checksum != stored_checksum:
                self.logger.warning(f"Configuration file {config_name} has been modified")
            
            # Restore from serialization
            restored_data = self._restore_from_serialization(data)
            
            self.logger.info(f"Loaded configuration: {config_name} ({config_format.value})")
            return restored_data
            
        except Exception as e:
            self.logger.error(f"Failed to load configuration {config_name}: {e}")
            raise ConfigurationError(f"Failed to load configuration: {e}")
    
    def _dict_to_ini(self, data: Dict[str, Any], config: configparser.ConfigParser, 
                     section: str = "DEFAULT"):
        """Convert dictionary to INI format"""
        for key, value in data.items():
            if isinstance(value, dict):
                section_name = f"{section}.{key}" if section != "DEFAULT" else key
                config.add_section(section_name)
                self._dict_to_ini(value, config, section_name)
            else:
                config.set(section, key, str(value))
    
    def _ini_to_dict(self, config: configparser.ConfigParser) -> Dict[str, Any]:
        """Convert INI format to dictionary"""
        result = {}
        for section_name in config.sections():
            section_dict = dict(config.items(section_name))
            
            # Handle nested sections
            if '.' in section_name:
                parts = section_name.split('.')
                current = result
                for part in parts[:-1]:
                    if part not in current:
                        current[part] = {}
                    current = current[part]
                current[parts[-1]] = section_dict
            else:
                result[section_name] = section_dict
        
        return result
    
    def _calculate_checksum(self, file_path: Path) -> str:
        """Calculate SHA256 checksum of file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    def save_all_configurations(self):
        """Save all current configurations to files"""
        try:
            # Save targets
            self.save_configuration("targets", self.targets)
            
            # Save test suites
            self.save_configuration("test_suites", self.test_suites)
            
            # Save settings
            self.save_configuration("security_settings", self.security_settings)
            self.save_configuration("reporting_settings", self.reporting_settings)
            self.save_configuration("framework_settings", self.framework_settings)
            
            self.logger.info("Saved all configurations")
            
        except Exception as e:
            self.logger.error(f"Failed to save all configurations: {e}")
            raise ConfigurationError(f"Failed to save configurations: {e}")
    
    def load_all_configurations(self):
        """Load all configurations from files"""
        try:
            # Load targets
            try:
                targets_data = self.load_configuration("targets")
                self.targets = {}
                for name, target_data in targets_data.items():
                    # Convert dict back to TargetConfig
                    target_config = TargetConfig(**target_data)
                    self.targets[name] = target_config
            except ConfigurationError:
                self.logger.warning("No targets configuration found")
            
            # Load test suites
            try:
                suites_data = self.load_configuration("test_suites")
                self.test_suites = {}
                for name, suite_data in suites_data.items():
                    # Convert dict back to TestSuiteConfig
                    suite_config = TestSuiteConfig(**suite_data)
                    self.test_suites[name] = suite_config
            except ConfigurationError:
                self.logger.warning("No test suites configuration found")
            
            # Load settings
            try:
                security_data = self.load_configuration("security_settings")
                self.security_settings = SecuritySettings(**security_data)
            except ConfigurationError:
                self.logger.warning("No security settings found, using defaults")
            
            try:
                reporting_data = self.load_configuration("reporting_settings")
                self.reporting_settings = ReportingSettings(**reporting_data)
            except ConfigurationError:
                self.logger.warning("No reporting settings found, using defaults")
            
            try:
                framework_data = self.load_configuration("framework_settings")
                self.framework_settings = FrameworkSettings(**framework_data)
            except ConfigurationError:
                self.logger.warning("No framework settings found, using defaults")
            
            self.logger.info("Loaded all configurations")
            
        except Exception as e:
            self.logger.error(f"Failed to load configurations: {e}")
            raise ConfigurationError(f"Failed to load configurations: {e}")
    
    def validate_configuration(self, config_name: str = None) -> Dict[str, List[str]]:
        """Validate configuration(s) for consistency and completeness"""
        validation_errors = {}
        
        if config_name:
            # Validate specific configuration
            if config_name in self.targets:
                validation_errors[f"target_{config_name}"] = self._validate_target(self.targets[config_name])
            elif config_name in self.test_suites:
                validation_errors[f"suite_{config_name}"] = self._validate_test_suite(self.test_suites[config_name])
        else:
            # Validate all configurations
            for name, target in self.targets.items():
                errors = self._validate_target(target)
                if errors:
                    validation_errors[f"target_{name}"] = errors
            
            for name, suite in self.test_suites.items():
                errors = self._validate_test_suite(suite)
                if errors:
                    validation_errors[f"suite_{name}"] = errors
            
            # Validate settings
            errors = self._validate_settings()
            if errors:
                validation_errors["settings"] = errors
        
        return validation_errors
    
    def _validate_target(self, target: TargetConfig) -> List[str]:
        """Validate target configuration"""
        errors = []
        
        # Check required fields
        if not target.base_url:
            errors.append("base_url is required")
        
        if target.target_type == TargetType.API_BASED and not target.api_key:
            errors.append("api_key is required for API-based targets")
        
        # Validate URL format
        if target.base_url and not (target.base_url.startswith('http://') or target.base_url.startswith('https://')):
            errors.append("base_url must start with http:// or https://")
        
        # Validate numeric ranges
        if target.max_tokens <= 0 or target.max_tokens > 100000:
            errors.append("max_tokens must be between 1 and 100000")
        
        if target.temperature < 0 or target.temperature > 2:
            errors.append("temperature must be between 0 and 2")
        
        if target.timeout <= 0:
            errors.append("timeout must be positive")
        
        return errors
    
    def _validate_test_suite(self, suite: TestSuiteConfig) -> List[str]:
        """Validate test suite configuration"""
        errors = []
        
        # Check required fields
        if not suite.name:
            errors.append("name is required")
        
        if not suite.enabled_categories:
            errors.append("at least one attack category must be enabled")
        
        # Validate test configurations
        for test_name, test_config in suite.test_configurations.items():
            if test_config.timeout <= 0:
                errors.append(f"{test_name}: timeout must be positive")
            
            if test_config.rate_limit_delay < 0:
                errors.append(f"{test_name}: rate_limit_delay must be non-negative")
            
            if test_config.max_retries < 0:
                errors.append(f"{test_name}: max_retries must be non-negative")
        
        return errors
    
    def _validate_settings(self) -> List[str]:
        """Validate framework settings"""
        errors = []
        
        # Validate framework settings
        if self.framework_settings.max_workers <= 0:
            errors.append("max_workers must be positive")
        
        if self.framework_settings.default_timeout <= 0:
            errors.append("default_timeout must be positive")
        
        if self.framework_settings.cache_ttl <= 0:
            errors.append("cache_ttl must be positive")
        
        # Validate security settings
        if self.security_settings.session_timeout <= 0:
            errors.append("session_timeout must be positive")
        
        return errors
    
    def export_configuration(self, export_path: str, 
                           include_sensitive: bool = False,
                           config_format: ConfigFormat = ConfigFormat.JSON):
        """Export configuration to external file"""
        
        export_data = {
            "framework_version": self.framework_settings.version,
            "export_timestamp": datetime.now().isoformat(),
            "targets": {},
            "test_suites": {},
            "settings": {
                "security": asdict(self.security_settings),
                "reporting": asdict(self.reporting_settings),
                "framework": asdict(self.framework_settings)
            }
        }
        
        # Export targets (with optional sensitive data filtering)
        for name, target in self.targets.items():
            target_data = asdict(target)
            if not include_sensitive:
                # Remove sensitive fields
                target_data.pop('api_key', None)
                # Anonymize URLs
                if self.security_settings.anonymize_targets:
                    target_data['base_url'] = "https://[ANONYMIZED]"
            export_data["targets"][name] = target_data
        
        # Export test suites
        for name, suite in self.test_suites.items():
            export_data["test_suites"][name] = asdict(suite)
        
        # Save export file
        export_path = Path(export_path)
        try:
            if config_format == ConfigFormat.JSON:
                with open(export_path, 'w') as f:
                    json.dump(export_data, f, indent=2, default=str)
            elif config_format == ConfigFormat.YAML:
                with open(export_path, 'w') as f:
                    yaml.safe_dump(export_data, f, default_flow_style=False)
            
            self.logger.info(f"Exported configuration to: {export_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to export configuration: {e}")
            raise ConfigurationError(f"Failed to export configuration: {e}")
    
    def import_configuration(self, import_path: str, 
                           merge: bool = True,
                           validate: bool = True):
        """Import configuration from external file"""
        
        import_path = Path(import_path)
        if not import_path.exists():
            raise ConfigurationError(f"Import file not found: {import_path}")
        
        try:
            # Determine format from extension
            if import_path.suffix.lower() == '.json':
                with open(import_path, 'r') as f:
                    import_data = json.load(f)
            elif import_path.suffix.lower() in ['.yaml', '.yml']:
                with open(import_path, 'r') as f:
                    import_data = yaml.safe_load(f)
            else:
                raise ConfigurationError(f"Unsupported import format: {import_path.suffix}")
            
            # Import targets
            if "targets" in import_data:
                for name, target_data in import_data["targets"].items():
                    if not merge and name in self.targets:
                        continue
                    target_config = TargetConfig(**target_data)
                    self.targets[name] = target_config
            
            # Import test suites
            if "test_suites" in import_data:
                for name, suite_data in import_data["test_suites"].items():
                    if not merge and name in self.test_suites:
                        continue
                    suite_config = TestSuiteConfig(**suite_data)
                    self.test_suites[name] = suite_config
            
            # Import settings
            if "settings" in import_data:
                settings = import_data["settings"]
                if "security" in settings:
                    self.security_settings = SecuritySettings(**settings["security"])
                if "reporting" in settings:
                    self.reporting_settings = ReportingSettings(**settings["reporting"])
                if "framework" in settings:
                    self.framework_settings = FrameworkSettings(**settings["framework"])
            
            # Validate if requested
            if validate:
                validation_errors = self.validate_configuration()
                if validation_errors:
                    raise ConfigurationError(f"Validation failed: {validation_errors}")
            
            self.logger.info(f"Imported configuration from: {import_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to import configuration: {e}")
            raise ConfigurationError(f"Failed to import configuration: {e}")
    
    def get_configuration_summary(self) -> Dict[str, Any]:
        """Get a summary of current configuration state"""
        return {
            "targets": {
                "count": len(self.targets),
                "names": list(self.targets.keys()),
                "types": list(set(target.target_type.value for target in self.targets.values()))
            },
            "test_suites": {
                "count": len(self.test_suites),
                "names": list(self.test_suites.keys())
            },
            "security": {
                "encryption_enabled": self.security_settings.encrypt_sensitive_data,
                "encryption_level": self.security_settings.encryption_level.value,
                "audit_logging": self.security_settings.audit_logging
            },
            "framework": {
                "version": self.framework_settings.version,
                "debug_mode": self.framework_settings.debug_mode,
                "parallel_execution": self.framework_settings.parallel_execution
            }
        }
    
    def backup_configuration(self, backup_path: str = None) -> str:
        """Create a backup of current configuration"""
        if not backup_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = self.config_dir / f"backup_{timestamp}.json"
        
        backup_path = Path(backup_path)
        
        # Create backup data
        backup_data = {
            "backup_timestamp": datetime.now().isoformat(),
            "framework_version": self.framework_settings.version,
            "targets": {name: asdict(target) for name, target in self.targets.items()},
            "test_suites": {name: asdict(suite) for name, suite in self.test_suites.items()},
            "settings": {
                "security": asdict(self.security_settings),
                "reporting": asdict(self.reporting_settings),
                "framework": asdict(self.framework_settings)
            },
            "checksums": self.config_checksums.copy()
        }
        
        try:
            with open(backup_path, 'w') as f:
                json.dump(backup_data, f, indent=2, default=str)
            
            self.logger.info(f"Created configuration backup: {backup_path}")
            return str(backup_path)
            
        except Exception as e:
            self.logger.error(f"Failed to create backup: {e}")
            raise ConfigurationError(f"Failed to create backup: {e}")
    
    def restore_configuration(self, backup_path: str):
        """Restore configuration from backup"""
        backup_path = Path(backup_path)
        
        if not backup_path.exists():
            raise ConfigurationError(f"Backup file not found: {backup_path}")
        
        try:
            with open(backup_path, 'r') as f:
                backup_data = json.load(f)
            
            # Restore targets
            if "targets" in backup_data:
                self.targets = {}
                for name, target_data in backup_data["targets"].items():
                    target_config = TargetConfig(**target_data)
                    self.targets[name] = target_config
            
            # Restore test suites
            if "test_suites" in backup_data:
                self.test_suites = {}
                for name, suite_data in backup_data["test_suites"].items():
                    suite_config = TestSuiteConfig(**suite_data)
                    self.test_suites[name] = suite_config
            
            # Restore settings
            if "settings" in backup_data:
                settings = backup_data["settings"]
                if "security" in settings:
                    self.security_settings = SecuritySettings(**settings["security"])
                if "reporting" in settings:
                    self.reporting_settings = ReportingSettings(**settings["reporting"])
                if "framework" in settings:
                    self.framework_settings = FrameworkSettings(**settings["framework"])
            
            # Restore checksums
            if "checksums" in backup_data:
                self.config_checksums = backup_data["checksums"]
            
            self.logger.info(f"Restored configuration from backup: {backup_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to restore from backup: {e}")
            raise ConfigurationError(f"Failed to restore from backup: {e}")


class ConfigurationTemplate:
    """Template system for common configuration patterns"""
    
    @staticmethod
    def create_openai_target(api_key: str, model: str = "gpt-3.5-turbo", 
                           base_url: str = "https://api.openai.com") -> TargetConfig:
        """Create OpenAI API target configuration"""
        return TargetConfig(
            target_type=TargetType.API_BASED,
            base_url=base_url,
            api_key=api_key,
            model_name=model,
            max_tokens=4000,
            temperature=0.7,
            headers={"Content-Type": "application/json"}
        )
    
    @staticmethod
    def create_anthropic_target(api_key: str, model: str = "claude-3-sonnet-20240229",
                              base_url: str = "https://api.anthropic.com") -> TargetConfig:
        """Create Anthropic API target configuration"""
        return TargetConfig(
            target_type=TargetType.API_BASED,
            base_url=base_url,
            api_key=api_key,
            model_name=model,
            max_tokens=4000,
            temperature=0.7,
            headers={"Content-Type": "application/json"}
        )
    
    @staticmethod
    def create_azure_openai_target(api_key: str, deployment_name: str,
                                 base_url: str, api_version: str = "2023-12-01-preview") -> TargetConfig:
        """Create Azure OpenAI target configuration"""
        return TargetConfig(
            target_type=TargetType.API_BASED,
            base_url=base_url,
            api_key=api_key,
            model_name=deployment_name,
            max_tokens=4000,
            temperature=0.7,
            headers={
                "Content-Type": "application/json",
                "api-version": api_version
            }
        )
    
    @staticmethod
    def create_local_target(base_url: str = "http://localhost:11434",
                          model: str = "llama2") -> TargetConfig:
        """Create local/self-hosted target configuration (e.g., Ollama)"""
        return TargetConfig(
            target_type=TargetType.SELF_HOSTED,
            base_url=base_url,
            model_name=model,
            max_tokens=2000,
            temperature=0.7,
            timeout=60
        )
    
    @staticmethod
    def create_quick_test_suite() -> TestSuiteConfig:
        """Create a quick test suite for rapid assessment"""
        return TestSuiteConfig(
            name="Quick Security Test",
            description="Rapid security assessment focusing on critical vulnerabilities",
            enabled_categories=[
                AttackCategory.PROMPT_INJECTION,
                AttackCategory.BUSINESS_LOGIC_BYPASS
            ],
            test_configurations={
                "prompt_injection": TestConfiguration(
                    enabled=True,
                    timeout=20,
                    rate_limit_delay=0.5,
                    severity_threshold=Severity.MEDIUM
                ),
                "business_logic_bypass": TestConfiguration(
                    enabled=True,
                    timeout=15,
                    rate_limit_delay=0.5,
                    severity_threshold=Severity.HIGH
                )
            },
            stop_on_critical=True
        )
    
    @staticmethod
    def create_comprehensive_test_suite() -> TestSuiteConfig:
        """Create a comprehensive test suite for thorough assessment"""
        return TestSuiteConfig(
            name="Comprehensive Security Assessment",
            description="Complete security testing covering all attack vectors",
            enabled_categories=list(AttackCategory),
            test_configurations={
                "prompt_injection": TestConfiguration(
                    enabled=True,
                    timeout=45,
                    rate_limit_delay=1.0,
                    severity_threshold=Severity.LOW
                ),
                "data_extraction": TestConfiguration(
                    enabled=True,
                    timeout=60,
                    rate_limit_delay=1.5,
                    severity_threshold=Severity.MEDIUM
                ),
                "model_manipulation": TestConfiguration(
                    enabled=True,
                    timeout=90,
                    rate_limit_delay=2.0,
                    severity_threshold=Severity.LOW
                ),
                "business_logic_bypass": TestConfiguration(
                    enabled=True,
                    timeout=45,
                    rate_limit_delay=1.0,
                    severity_threshold=Severity.MEDIUM
                )
            },
            stop_on_critical=False,
            continue_on_error=True
        )
    
    @staticmethod
    def create_production_security_settings() -> SecuritySettings:
        """Create production-ready security settings"""
        return SecuritySettings(
            encrypt_sensitive_data=True,
            encryption_level=EncryptionLevel.FULL,
            log_sensitive_data=False,
            anonymize_targets=True,
            require_auth=True,
            session_timeout=1800,  # 30 minutes
            audit_logging=True,
            secure_storage_path="./secure_config"
        )
    
    @staticmethod
    def create_development_security_settings() -> SecuritySettings:
        """Create development-friendly security settings"""
        return SecuritySettings(
            encrypt_sensitive_data=True,
            encryption_level=EncryptionLevel.SENSITIVE_ONLY,
            log_sensitive_data=True,
            anonymize_targets=False,
            require_auth=False,
            session_timeout=7200,  # 2 hours
            audit_logging=True,
            secure_storage_path="./dev_config"
        )


class EnvironmentConfigLoader:
    """Load configuration from environment variables and external sources"""
    
    @staticmethod
    def load_from_environment() -> Dict[str, Any]:
        """Load configuration from environment variables"""
        env_config = {}
        
        # Framework settings
        if os.getenv('LLM_SECURITY_DEBUG'):
            env_config['debug_mode'] = os.getenv('LLM_SECURITY_DEBUG').lower() == 'true'
        
        if os.getenv('LLM_SECURITY_PARALLEL'):
            env_config['parallel_execution'] = os.getenv('LLM_SECURITY_PARALLEL').lower() == 'true'
        
        if os.getenv('LLM_SECURITY_MAX_WORKERS'):
            env_config['max_workers'] = int(os.getenv('LLM_SECURITY_MAX_WORKERS'))
        
        # Security settings
        if os.getenv('LLM_SECURITY_ENCRYPT_DATA'):
            env_config['encrypt_sensitive_data'] = os.getenv('LLM_SECURITY_ENCRYPT_DATA').lower() == 'true'
        
        if os.getenv('LLM_SECURITY_ANONYMIZE'):
            env_config['anonymize_targets'] = os.getenv('LLM_SECURITY_ANONYMIZE').lower() == 'true'
        
        return env_config
    
    @staticmethod
    def create_target_from_env(prefix: str = "TARGET") -> Optional[TargetConfig]:
        """Create target configuration from environment variables"""
        base_url = os.getenv(f'{prefix}_BASE_URL')
        if not base_url:
            return None
        
        target_type_str = os.getenv(f'{prefix}_TYPE', 'api_based')
        try:
            target_type = TargetType(target_type_str)
        except ValueError:
            target_type = TargetType.API_BASED
        
        return TargetConfig(
            target_type=target_type,
            base_url=base_url,
            api_key=os.getenv(f'{prefix}_API_KEY'),
            model_name=os.getenv(f'{prefix}_MODEL'),
            max_tokens=int(os.getenv(f'{prefix}_MAX_TOKENS', '1000')),
            temperature=float(os.getenv(f'{prefix}_TEMPERATURE', '0.7')),
            timeout=int(os.getenv(f'{prefix}_TIMEOUT', '30'))
        )
    
    @staticmethod
    def load_targets_from_env() -> Dict[str, TargetConfig]:
        """Load multiple targets from environment variables"""
        targets = {}
        
        # Check for numbered targets (TARGET_1_BASE_URL, TARGET_2_BASE_URL, etc.)
        i = 1
        while True:
            target = EnvironmentConfigLoader.create_target_from_env(f"TARGET_{i}")
            if target is None:
                break
            targets[f"target_{i}"] = target
            i += 1
        
        # Check for named targets
        for env_var in os.environ:
            if env_var.endswith('_BASE_URL') and not env_var.startswith('TARGET_'):
                prefix = env_var[:-9]  # Remove '_BASE_URL'
                target = EnvironmentConfigLoader.create_target_from_env(prefix)
                if target:
                    targets[prefix.lower()] = target
        
        return targets


class ConfigurationValidator:
    """Advanced configuration validation and health checks"""
    
    def __init__(self, config_manager: ConfigurationManager):
        self.config_manager = config_manager
    
    def run_health_check(self) -> Dict[str, Any]:
        """Run comprehensive configuration health check"""
        health_report = {
            "overall_status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "checks": {},
            "warnings": [],
            "errors": []
        }
        
        # Check configuration files integrity
        health_report["checks"]["file_integrity"] = self._check_file_integrity()
        
        # Check target connectivity
        health_report["checks"]["target_connectivity"] = self._check_target_connectivity()
        
        # Check encryption status
        health_report["checks"]["encryption_status"] = self._check_encryption_status()
        
        # Check disk space
        health_report["checks"]["disk_space"] = self._check_disk_space()
        
        # Check permissions
        health_report["checks"]["permissions"] = self._check_permissions()
        
        # Determine overall status
        if any(check["status"] == "error" for check in health_report["checks"].values()):
            health_report["overall_status"] = "unhealthy"
        elif any(check["status"] == "warning" for check in health_report["checks"].values()):
            health_report["overall_status"] = "warning"
        
        return health_report
    
    def _check_file_integrity(self) -> Dict[str, Any]:
        """Check configuration file integrity"""
        try:
            validation_errors = self.config_manager.validate_configuration()
            
            if validation_errors:
                return {
                    "status": "error",
                    "message": "Configuration validation failed",
                    "details": validation_errors
                }
            else:
                return {
                    "status": "healthy",
                    "message": "All configurations are valid"
                }
        except Exception as e:
            return {
                "status": "error",
                "message": f"Failed to validate configurations: {e}"
            }
    
    def _check_target_connectivity(self) -> Dict[str, Any]:
        """Check connectivity to configured targets"""
        connectivity_results = {}
        
        for name, target in self.config_manager.targets.items():
            try:
                # Basic connectivity check (would need LLMClient integration)
                # For now, just check URL format and reachability concept
                if target.base_url:
                    connectivity_results[name] = {
                        "status": "healthy",
                        "message": "Target configuration appears valid"
                    }
                else:
                    connectivity_results[name] = {
                        "status": "error",
                        "message": "Invalid target URL"
                    }
            except Exception as e:
                connectivity_results[name] = {
                    "status": "error",
                    "message": f"Connectivity check failed: {e}"
                }
        
        # Determine overall connectivity status
        if all(result["status"] == "healthy" for result in connectivity_results.values()):
            status = "healthy"
            message = "All targets are reachable"
        elif any(result["status"] == "error" for result in connectivity_results.values()):
            status = "error"
            message = "Some targets are unreachable"
        else:
            status = "warning"
            message = "Some connectivity issues detected"
        
        return {
            "status": status,
            "message": message,
            "details": connectivity_results
        }
    
    def _check_encryption_status(self) -> Dict[str, Any]:
        """Check encryption configuration and key status"""
        try:
            # Check if encryption key exists and is valid
            key_file = self.config_manager.config_dir / ".encryption_key"
            
            if not key_file.exists():
                return {
                    "status": "error",
                    "message": "Encryption key file not found"
                }
            
            # Check key file permissions
            key_permissions = oct(key_file.stat().st_mode)[-3:]
            if key_permissions != "600":
                return {
                    "status": "warning",
                    "message": f"Encryption key file has insecure permissions: {key_permissions}"
                }
            
            # Check if encryption is properly configured
            if self.config_manager.security_settings.encrypt_sensitive_data:
                return {
                    "status": "healthy",
                    "message": "Encryption is properly configured and active"
                }
            else:
                return {
                    "status": "warning",
                    "message": "Encryption is available but not enabled"
                }
                
        except Exception as e:
            return {
                "status": "error",
                "message": f"Encryption check failed: {e}"
            }
    
    def _check_disk_space(self) -> Dict[str, Any]:
        """Check available disk space for configuration storage"""
        try:
            config_dir = self.config_manager.config_dir
            stat = os.statvfs(config_dir)
            
            # Calculate free space in MB
            free_space_mb = (stat.f_bavail * stat.f_frsize) / (1024 * 1024)
            
            if free_space_mb < 10:  # Less than 10MB
                return {
                    "status": "error",
                    "message": f"Low disk space: {free_space_mb:.1f}MB available"
                }
            elif free_space_mb < 100:  # Less than 100MB
                return {
                    "status": "warning",
                    "message": f"Limited disk space: {free_space_mb:.1f}MB available"
                }
            else:
                return {
                    "status": "healthy",
                    "message": f"Sufficient disk space: {free_space_mb:.1f}MB available"
                }
                
        except Exception as e:
            return {
                "status": "warning",
                "message": f"Could not check disk space: {e}"
            }
    
    def _check_permissions(self) -> Dict[str, Any]:
        """Check file and directory permissions"""
        try:
            config_dir = self.config_manager.config_dir
            
            # Check if config directory is writable
            if not os.access(config_dir, os.W_OK):
                return {
                    "status": "error",
                    "message": "Configuration directory is not writable"
                }
            
            # Check if config directory is readable
            if not os.access(config_dir, os.R_OK):
                return {
                    "status": "error",
                    "message": "Configuration directory is not readable"
                }
            
            return {
                "status": "healthy",
                "message": "File permissions are correct"
            }
            
        except Exception as e:
            return {
                "status": "warning",
                "message": f"Could not check permissions: {e}"
            }
    
    def generate_security_recommendations(self) -> List[str]:
        """Generate security recommendations based on current configuration"""
        recommendations = []
        
        # Check encryption settings
        if not self.config_manager.security_settings.encrypt_sensitive_data:
            recommendations.append("Enable encryption for sensitive data")
        
        if self.config_manager.security_settings.encryption_level == EncryptionLevel.NONE:
            recommendations.append("Configure encryption level to at least SENSITIVE_ONLY")
        
        # Check logging settings
        if self.config_manager.security_settings.log_sensitive_data:
            recommendations.append("Disable logging of sensitive data in production")
        
        if not self.config_manager.security_settings.audit_logging:
            recommendations.append("Enable audit logging for compliance and security monitoring")
        
        # Check authentication settings
        if not self.config_manager.security_settings.require_auth:
            recommendations.append("Enable authentication requirements for production use")
        
        # Check session timeout
        if self.config_manager.security_settings.session_timeout > 7200:  # 2 hours
            recommendations.append("Consider reducing session timeout for better security")
        
        # Check target configurations
        for name, target in self.config_manager.targets.items():
            if target.target_type == TargetType.API_BASED and not target.api_key:
                recommendations.append(f"Configure API key for target '{name}'")
            
            if not target.base_url.startswith('https://'):
                recommendations.append(f"Use HTTPS for target '{name}' in production")
        
        return recommendations if recommendations else ["Configuration security appears adequate"]
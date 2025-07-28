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

import requests
import time
import json
from typing import Dict, Optional, Union, Any
from urllib.parse import urljoin, urlparse
import ssl
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from requests.exceptions import RequestException, Timeout, ConnectionError
from llm_scan import TargetConfig, SecurityLogger, TargetType

class LLMClientError(Exception):
    """Custom exception for LLM client errors"""
    pass

class LLMClient:
    """Universal client for LLM security testing across different platforms"""
    
    def __init__(self, target_config: TargetConfig, logger: SecurityLogger):
        self.config = target_config
        self.logger = logger
        self.session = self._create_session()
        self.last_request_time = 0
        
    def _create_session(self) -> requests.Session:
        """Create configured HTTP session with retries and security settings"""
        session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE", "POST"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Set headers
        session.headers.update({
            'User-Agent': 'LLM-Security-Testing-Framework/1.0',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        })
        
        # Add custom headers from config
        if self.config.headers:
            session.headers.update(self.config.headers)
        
        # Add authentication if provided
        if self.config.api_key:
            session.headers.update(self._get_auth_headers())
        
        return session
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """Generate authentication headers based on target type"""
        auth_headers = {}
        
        if self.config.target_type == TargetType.API_BASED:
            # Common API authentication patterns
            if "openai" in self.config.base_url.lower():
                auth_headers['Authorization'] = f'Bearer {self.config.api_key}'
            elif "anthropic" in self.config.base_url.lower():
                auth_headers['x-api-key'] = self.config.api_key
            elif "azure" in self.config.base_url.lower():
                auth_headers['api-key'] = self.config.api_key
            else:
                # Generic bearer token
                auth_headers['Authorization'] = f'Bearer {self.config.api_key}'
        
        elif self.config.target_type == TargetType.CHATBOT_INTERFACE:
            # Custom authentication for chatbot interfaces
            auth_headers['X-API-Key'] = self.config.api_key
        
        return auth_headers
    
    def _rate_limit(self):
        """Implement rate limiting to avoid overwhelming targets"""
        if self.config.rate_limit_delay > 0:
            current_time = time.time()
            time_since_last = current_time - self.last_request_time
            
            if time_since_last < self.config.rate_limit_delay:
                sleep_time = self.config.rate_limit_delay - time_since_last
                time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def _build_request_payload(self, prompt: str) -> Dict[str, Any]:
        """Build request payload based on target type and platform"""
        
        if self.config.target_type == TargetType.API_BASED:
            # OpenAI-style API
            if "openai" in self.config.base_url.lower():
                return {
                    "model": self.config.model_name or "gpt-3.5-turbo",
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": self.config.max_tokens,
                    "temperature": self.config.temperature
                }
            
            # Anthropic-style API
            elif "anthropic" in self.config.base_url.lower():
                return {
                    "model": self.config.model_name or "claude-3-sonnet-20240229",
                    "max_tokens": self.config.max_tokens,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": self.config.temperature
                }
            
            # Azure OpenAI
            elif "azure" in self.config.base_url.lower():
                return {
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": self.config.max_tokens,
                    "temperature": self.config.temperature
                }
            
            # Generic API format
            else:
                return {
                    "prompt": prompt,
                    "max_tokens": self.config.max_tokens,
                    "temperature": self.config.temperature,
                    "model": self.config.model_name
                }
        
        elif self.config.target_type == TargetType.SELF_HOSTED:
            # Common self-hosted model formats (Ollama, vLLM, etc.)
            return {
                "model": self.config.model_name or "llama2",
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": self.config.temperature,
                    "num_predict": self.config.max_tokens
                }
            }
        
        elif self.config.target_type == TargetType.CHATBOT_INTERFACE:
            # Custom chatbot interface
            return {
                "message": prompt,
                "max_length": self.config.max_tokens,
                "temperature": self.config.temperature
            }
        
        return {"prompt": prompt}
    
    def _extract_response_text(self, response_data: Dict[str, Any]) -> str:
        """Extract text response from different API response formats"""
        
        try:
            # OpenAI format
            if "choices" in response_data:
                if "message" in response_data["choices"][0]:
                    return response_data["choices"][0]["message"]["content"]
                elif "text" in response_data["choices"][0]:
                    return response_data["choices"][0]["text"]
            
            # Anthropic format
            elif "content" in response_data:
                if isinstance(response_data["content"], list):
                    return response_data["content"][0].get("text", "")
                return response_data["content"]
            
            # Self-hosted (Ollama, etc.)
            elif "response" in response_data:
                return response_data["response"]
            
            # Generic formats
            elif "text" in response_data:
                return response_data["text"]
            elif "message" in response_data:
                return response_data["message"]
            elif "output" in response_data:
                return response_data["output"]
            
            # If no standard format found, return full response as string
            return str(response_data)
            
        except (KeyError, IndexError, TypeError) as e:
            self.logger.log_warning(f"Failed to extract response text: {e}")
            return str(response_data)

    def send_prompt(self, prompt: str) -> str:
        """Send prompt to LLM target and return response"""
        
        self._rate_limit()
        
        try:
            # Build request payload
            payload = self._build_request_payload(prompt)
            
            # Determine endpoint
            endpoint = self._get_endpoint()
            
            self.logger.logger.debug(f"Sending request to {endpoint}")
            self.logger.logger.debug(f"Payload: {json.dumps(payload, indent=2)}")
            
            # Send request
            response = self.session.post(
                endpoint,
                json=payload,
                timeout=self.config.timeout
            )
            
            # Log response details
            self.logger.logger.debug(f"Response status: {response.status_code}")
            self.logger.logger.debug(f"Response headers: {dict(response.headers)}")
            
            # Handle different response codes
            if response.status_code == 200:
                response_data = response.json()
                return self._extract_response_text(response_data)
            
            elif response.status_code == 401:
                raise LLMClientError("Authentication failed - check API key")
            
            elif response.status_code == 403:
                raise LLMClientError("Access forbidden - insufficient permissions")
            
            elif response.status_code == 429:
                raise LLMClientError("Rate limit exceeded - reduce request frequency")
            
            elif response.status_code == 400:
                error_msg = "Bad request"
                try:
                    error_data = response.json()
                    if "error" in error_data:
                        error_msg = f"Bad request: {error_data['error']}"
                except:
                    pass
                raise LLMClientError(error_msg)
            
            elif response.status_code == 404:
                raise LLMClientError("Endpoint not found - check base URL and model name")
            
            elif response.status_code == 500:
                raise LLMClientError("Server error - the target LLM service is experiencing issues")
            
            elif response.status_code == 502:
                raise LLMClientError("Bad gateway - proxy or load balancer error")
            
            elif response.status_code == 503:
                raise LLMClientError("Service unavailable - target service is temporarily down")
            
            else:
                raise LLMClientError(f"HTTP {response.status_code}: {response.text}")
        
        except requests.exceptions.SSLError as e:
            raise LLMClientError(f"SSL/TLS error: {str(e)} - check certificate configuration")
        
        except requests.exceptions.ConnectTimeout:
            raise LLMClientError(f"Connection timeout after {self.config.timeout}s - check network connectivity")
        
        except requests.exceptions.ReadTimeout:
            raise LLMClientError(f"Read timeout after {self.config.timeout}s - server response too slow")
        
        except requests.exceptions.ConnectionError as e:
            error_str = str(e).lower()
            if "connection refused" in error_str:
                raise LLMClientError("Connection refused - target service not running or wrong port")
            elif "name or service not known" in error_str or "nodename nor servname provided" in error_str:
                raise LLMClientError("DNS resolution failed - check hostname in base URL")
            elif "network is unreachable" in error_str:
                raise LLMClientError("Network unreachable - check internet connectivity")
            else:
                raise LLMClientError(f"Connection error: {str(e)}")
        
        except requests.exceptions.TooManyRedirects:
            raise LLMClientError("Too many redirects - check base URL configuration")
        
        except requests.exceptions.InvalidURL:
            raise LLMClientError("Invalid URL format - check base URL configuration")
        
        except requests.exceptions.RequestException as e:
            if isinstance(e, Timeout):
                raise LLMClientError(f"Request timeout after {self.config.timeout}s")
            else:
                raise LLMClientError(f"Request failed: {str(e)}")
        
        except json.JSONDecodeError as e:
            raise LLMClientError(f"Invalid JSON response from target: {str(e)}")
        
        except UnicodeDecodeError as e:
            raise LLMClientError(f"Response encoding error: {str(e)}")
        
        except Exception as e:
            raise LLMClientError(f"Unexpected error: {str(e)}")
    
    def _get_endpoint(self) -> str:
        """Determine the correct API endpoint based on target type"""
        
        base_url = self.config.base_url.rstrip('/')
        
        if self.config.target_type == TargetType.API_BASED:
            if "openai" in base_url.lower():
                return f"{base_url}/v1/chat/completions"
            elif "anthropic" in base_url.lower():
                return f"{base_url}/v1/messages"
            elif "azure" in base_url.lower():
                # Azure OpenAI has deployment-specific endpoints
                return f"{base_url}/openai/deployments/{self.config.model_name}/chat/completions?api-version=2023-12-01-preview"
            else:
                return f"{base_url}/v1/completions"
        
        elif self.config.target_type == TargetType.SELF_HOSTED:
            return f"{base_url}/api/generate"
        
        elif self.config.target_type == TargetType.CHATBOT_INTERFACE:
            return f"{base_url}/chat"
        
        return base_url
    
    def test_connection(self) -> bool:
        """Test connection to target with a simple prompt"""
        try:
            test_response = self.send_prompt("Hello, this is a connection test.")
            return len(test_response.strip()) > 0
        except Exception as e:
            self.logger.log_error(f"Connection test failed: {str(e)}")
            return False
    
    def get_target_info(self) -> Dict[str, Any]:
        """Gather information about the target for reconnaissance"""
        info = {
            "target_type": self.config.target_type.value,
            "base_url": self.config.base_url,
            "model_name": self.config.model_name,
            "connection_status": "unknown"
        }
        
        # Test connection
        try:
            if self.test_connection():
                info["connection_status"] = "success"
                
                # Try to gather additional info with reconnaissance prompts
                recon_prompts = [
                    "What model are you?",
                    "What is your name?",
                    "What version are you?",
                    "Who created you?"
                ]
                
                responses = []
                for prompt in recon_prompts:
                    try:
                        response = self.send_prompt(prompt)
                        responses.append({"prompt": prompt, "response": response[:200]})
                    except:
                        continue
                
                info["reconnaissance"] = responses
            else:
                info["connection_status"] = "failed"
                
        except Exception as e:
            info["connection_status"] = f"error: {str(e)}"
        
        return info
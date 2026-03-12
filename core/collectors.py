"""
DataVault Collectors Module
Contains all data collection logic for different sources
"""

import requests
import socket
import json
from typing import Dict, List, Any
from datetime import datetime
from bs4 import BeautifulSoup

class IPInfoCollector:
    """Collects IP and domain information"""
    
    @staticmethod
    def collect(target: str) -> Dict[str, Any]:
        """
        Collect IP/domain information
        Args:
            target: IP address or domain name
        Returns:
            Dictionary with collected data
        """
        result = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "data": {},
            "error": None
        }
        
        try:
            # Basic DNS/IP resolution
            try:
                ip = socket.gethostbyname(target)
                result["data"]["resolved_ip"] = ip
            except socket.gaierror:
                result["data"]["resolved_ip"] = target
            
            # Try to get reverse DNS
            try:
                hostname = socket.gethostbyaddr(result["data"]["resolved_ip"])[0]
                result["data"]["reverse_dns"] = hostname
            except:
                result["data"]["reverse_dns"] = "N/A"
            
            # Try to get GeoIP data from API
            try:
                api_url = f"https://suicixde.com/api/geoip/1.1.1.1"
                response = requests.get(
                    api_url.replace("1.1.1.1", result["data"]["resolved_ip"]),
                    timeout=5,
                    headers={'User-Agent': 'DataVault/1.0'}
                )
                if response.status_code == 200:
                    geo_data = response.json()
                    result["data"]["geoip"] = geo_data
                    result["data"]["status"] = "complete"
                else:
                    result["data"]["status"] = "partial_data"
                    result["data"]["note"] = "GeoIP API unavailable"
            except:
                result["data"]["status"] = "partial_data"
                result["data"]["note"] = "Basic DNS resolution only"
            
        except Exception as e:
            result["error"] = str(e)
        
        return result


class BreachCollector:
    """Checks for breached emails/domains"""
    
    @staticmethod
    def collect(target: str) -> Dict[str, Any]:
        """
        Check if email/domain has been breached
        Args:
            target: Email or domain to check
        Returns:
            Dictionary with breach information
        """
        result = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "data": {},
            "error": None
        }
        
        try:
            # Using Have I Been Pwned API (free, no auth required)
            headers = {
                'User-Agent': 'DataVault/1.0'
            }
            
            # Check against HIBP
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{target}"
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                breaches = response.json()
                result["data"]["breached"] = True
                result["data"]["breach_count"] = len(breaches)
                result["data"]["breaches"] = [
                    {
                        "name": b.get("Name"),
                        "date": b.get("BreachDate"),
                        "title": b.get("Title")
                    }
                    for b in breaches
                ]
            elif response.status_code == 404:
                result["data"]["breached"] = False
                result["data"]["breach_count"] = 0
                result["data"]["breaches"] = []
            else:
                result["error"] = f"API returned status {response.status_code}"
        
        except Exception as e:
            result["error"] = str(e)
        
        return result


class WebScraper:
    """Scrapes web content"""
    
    @staticmethod
    def collect(url: str) -> Dict[str, Any]:
        """
        Scrape web page content
        Args:
            url: URL to scrape
        Returns:
            Dictionary with extracted data
        """
        result = {
            "target": url,
            "timestamp": datetime.now().isoformat(),
            "data": {},
            "error": None
        }
        
        try:
            # Ensure URL has protocol
            if not url.startswith(('http://', 'https://')):
                url = f'https://{url}'
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract basic info
            result["data"]["status_code"] = response.status_code
            result["data"]["content_length"] = len(response.content)
            result["data"]["title"] = soup.title.string if soup.title else "No title"
            
            # Extract meta description
            meta_desc = soup.find('meta', attrs={'name': 'description'})
            result["data"]["description"] = meta_desc.get('content', 'N/A') if meta_desc else 'N/A'
            
            # Count elements
            result["data"]["headings"] = len(soup.find_all(['h1', 'h2', 'h3']))
            result["data"]["links"] = len(soup.find_all('a'))
            result["data"]["images"] = len(soup.find_all('img'))
            
            # Extract all text
            text = soup.get_text()
            result["data"]["text_preview"] = text[:500]  # First 500 chars
            
        except Exception as e:
            result["error"] = str(e)
        
        return result


class VulnerabilityScanner:
    """Scans for vulnerabilities"""
    
    @staticmethod
    def collect(target: str) -> Dict[str, Any]:
        """
        Basic vulnerability scan simulation
        Args:
            target: Target URL or IP
        Returns:
            Dictionary with scan results
        """
        result = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "data": {},
            "error": None
        }
        
        try:
            # Ensure URL has protocol
            if not target.startswith(('http://', 'https://')):
                target = f'https://{target}'
            
            headers = {
                'User-Agent': 'DataVault/1.0'
            }
            
            response = requests.get(target, headers=headers, timeout=10)
            
            # Check for common headers
            result["data"]["checks"] = {
                "has_https": target.startswith('https://'),
                "has_hsts": 'strict-transport-security' in response.headers,
                "has_csp": 'content-security-policy' in response.headers,
                "has_x_frame_options": 'x-frame-options' in response.headers,
                "server_header": response.headers.get('server', 'Not disclosed'),
            }
            
            # Count issues
            issues = sum(1 for v in result["data"]["checks"].values() if not v and v is not True)
            result["data"]["security_score"] = max(0, 100 - (issues * 20))
            result["data"]["status_code"] = response.status_code
            
        except Exception as e:
            result["error"] = str(e)
        
        return result


class VPSMonitor:
    """Monitors VPS/Server health"""
    
    @staticmethod
    def collect(host: str) -> Dict[str, Any]:
        """
        Basic VPS monitoring (ping check)
        Args:
            host: Server hostname or IP
        Returns:
            Dictionary with server status
        """
        result = {
            "target": host,
            "timestamp": datetime.now().isoformat(),
            "data": {},
            "error": None
        }
        
        try:
            # Ping test (basic connectivity)
            response = requests.get(f'http://{host}', timeout=5)
            result["data"]["online"] = True
            result["data"]["status_code"] = response.status_code
            result["data"]["response_time"] = response.elapsed.total_seconds()
        except requests.ConnectionError:
            result["data"]["online"] = False
            result["data"]["error_type"] = "Connection refused"
        except requests.Timeout:
            result["data"]["online"] = False
            result["data"]["error_type"] = "Timeout"
        except Exception as e:
            result["error"] = str(e)
        
        return result

# Let's create the core WAF system components
# First, let's create the log parser and data structures

import json
import re
import pandas as pd
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import numpy as np

# Core data structures for the WAF system
class LogEntry:
    """Represents a parsed web server log entry"""
    def __init__(self, raw_log: str, log_format: str = "combined"):
        self.raw_log = raw_log
        self.parsed_data = {}
        self.normalized_data = {}
        self.timestamp = None
        self.parse_log(log_format)
    
    def parse_log(self, log_format: str):
        """Parse raw log entry into structured data"""
        if log_format == "combined":
            # Combined log format: %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"
            pattern = r'(\S+) (\S+) (\S+) \[([^\]]+)\] "([^"]*)" (\d+) (\S+) "([^"]*)" "([^"]*)"'
            match = re.match(pattern, self.raw_log)
            
            if match:
                self.parsed_data = {
                    'client_ip': match.group(1),
                    'remote_logname': match.group(2),
                    'remote_user': match.group(3),
                    'timestamp': match.group(4),
                    'request': match.group(5),
                    'status_code': int(match.group(6)),
                    'response_size': match.group(7),
                    'referer': match.group(8),
                    'user_agent': match.group(9)
                }
                
                # Parse request details
                if self.parsed_data['request']:
                    request_parts = self.parsed_data['request'].split(' ')
                    if len(request_parts) >= 2:
                        self.parsed_data['method'] = request_parts[0]
                        self.parsed_data['url'] = request_parts[1]
                        self.parsed_data['protocol'] = request_parts[2] if len(request_parts) > 2 else 'HTTP/1.1'
                
                # Parse timestamp
                try:
                    self.timestamp = datetime.strptime(
                        self.parsed_data['timestamp'], 
                        '%d/%b/%Y:%H:%M:%S %z'
                    )
                except:
                    self.timestamp = datetime.now()
    
    def normalize(self) -> Dict:
        """Normalize log entry for ML processing"""
        self.normalized_data = {
            'method': self.parsed_data.get('method', 'GET'),
            'path': self._normalize_path(self.parsed_data.get('url', '/')),
            'status_code': self.parsed_data.get('status_code', 200),
            'response_size': self._normalize_size(self.parsed_data.get('response_size', '0')),
            'user_agent_features': self._extract_ua_features(self.parsed_data.get('user_agent', '')),
            'request_features': self._extract_request_features(self.parsed_data.get('request', '')),
            'time_features': self._extract_time_features()
        }
        return self.normalized_data
    
    def _normalize_path(self, path: str) -> str:
        """Normalize URL paths by removing dynamic components"""
        # Remove query parameters
        path = path.split('?')[0]
        # Replace numeric IDs with placeholder
        path = re.sub(r'/\d+', '/[ID]', path)
        # Replace session tokens
        path = re.sub(r'/[a-f0-9]{32,}', '/[TOKEN]', path)
        return path
    
    def _normalize_size(self, size: str) -> int:
        """Normalize response size"""
        try:
            return int(size) if size != '-' else 0
        except:
            return 0
    
    def _extract_ua_features(self, user_agent: str) -> Dict:
        """Extract features from user agent string"""
        return {
            'is_bot': any(bot in user_agent.lower() for bot in ['bot', 'crawler', 'spider']),
            'browser_type': self._get_browser_type(user_agent),
            'os_type': self._get_os_type(user_agent),
            'ua_length': len(user_agent)
        }
    
    def _extract_request_features(self, request: str) -> Dict:
        """Extract features from request string"""
        return {
            'has_sql_injection': self._detect_sql_injection(request),
            'has_xss_attempt': self._detect_xss(request),
            'has_path_traversal': self._detect_path_traversal(request),
            'request_length': len(request),
            'has_encoded_chars': '%' in request,
            'suspicious_patterns': self._count_suspicious_patterns(request)
        }
    
    def _extract_time_features(self) -> Dict:
        """Extract temporal features"""
        if self.timestamp:
            return {
                'hour': self.timestamp.hour,
                'day_of_week': self.timestamp.weekday(),
                'is_weekend': self.timestamp.weekday() >= 5,
                'is_night': self.timestamp.hour < 6 or self.timestamp.hour > 22
            }
        return {'hour': 0, 'day_of_week': 0, 'is_weekend': False, 'is_night': False}
    
    def _get_browser_type(self, ua: str) -> str:
        """Identify browser type from user agent"""
        ua_lower = ua.lower()
        if 'chrome' in ua_lower:
            return 'chrome'
        elif 'firefox' in ua_lower:
            return 'firefox'
        elif 'safari' in ua_lower:
            return 'safari'
        elif 'edge' in ua_lower:
            return 'edge'
        else:
            return 'other'
    
    def _get_os_type(self, ua: str) -> str:
        """Identify OS type from user agent"""
        ua_lower = ua.lower()
        if 'windows' in ua_lower:
            return 'windows'
        elif 'mac' in ua_lower or 'darwin' in ua_lower:
            return 'mac'
        elif 'linux' in ua_lower:
            return 'linux'
        elif 'android' in ua_lower:
            return 'android'
        elif 'ios' in ua_lower:
            return 'ios'
        else:
            return 'other'
    
    def _detect_sql_injection(self, request: str) -> bool:
        """Detect potential SQL injection patterns"""
        sql_patterns = [
            r"(\bunion\b.*\bselect\b)",
            r"(\bselect\b.*\bfrom\b)",
            r"(\binsert\b.*\binto\b)",
            r"(\bdelete\b.*\bfrom\b)",
            r"(\bdrop\b.*\btable\b)",
            r"('.*or.*'.*=.*')",
            r"(--|\#)",
            r"(\bor\b.*1.*=.*1)",
            r"(\band\b.*1.*=.*1)"
        ]
        request_lower = request.lower()
        return any(re.search(pattern, request_lower) for pattern in sql_patterns)
    
    def _detect_xss(self, request: str) -> bool:
        """Detect potential XSS patterns"""
        xss_patterns = [
            r"<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>",
            r"javascript:",
            r"on\w+\s*=",
            r"<iframe\b",
            r"<object\b",
            r"<embed\b",
            r"<applet\b"
        ]
        request_lower = request.lower()
        return any(re.search(pattern, request_lower) for pattern in xss_patterns)
    
    def _detect_path_traversal(self, request: str) -> bool:
        """Detect potential path traversal patterns"""
        traversal_patterns = [
            r"\.\.\/",
            r"\.\.\\",
            r"%2e%2e%2f",
            r"%2e%2e\\",
            r"..%2f",
            r"..%5c"
        ]
        request_lower = request.lower()
        return any(re.search(pattern, request_lower) for pattern in traversal_patterns)
    
    def _count_suspicious_patterns(self, request: str) -> int:
        """Count suspicious patterns in request"""
        suspicious_chars = ['<', '>', '"', "'", '&', '%', ';', '(', ')', '{', '}']
        return sum(request.count(char) for char in suspicious_chars)

# Test the log parser with sample data
sample_logs = [
    '192.168.1.100 - - [26/Sep/2025:18:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326 "http://www.google.com" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"',
    '10.0.0.1 - - [26/Sep/2025:18:56:15 +0000] "POST /login.php HTTP/1.1" 200 1547 "-" "curl/7.64.1"',
    '192.168.1.100 - - [26/Sep/2025:18:56:45 +0000] "GET /admin/config.php?id=1\' OR 1=1-- HTTP/1.1" 403 0 "-" "sqlmap/1.4.7"',
    '10.0.0.1 - - [26/Sep/2025:18:57:12 +0000] "GET /search?q=<script>alert(\'XSS\')</script> HTTP/1.1" 200 3421 "http://evil.com" "Mozilla/5.0 (compatible; bot)"'
]

print("=== WAF Log Parser and Normalizer ===\n")

# Process sample logs
processed_logs = []
for i, log in enumerate(sample_logs):
    entry = LogEntry(log)
    normalized = entry.normalize()
    processed_logs.append({
        'raw': log,
        'parsed': entry.parsed_data,
        'normalized': normalized
    })
    
    print(f"Log Entry {i+1}:")
    print(f"Original: {log}")
    print(f"Method: {entry.parsed_data.get('method', 'N/A')}")
    print(f"URL: {entry.parsed_data.get('url', 'N/A')}")
    print(f"Status: {entry.parsed_data.get('status_code', 'N/A')}")
    print(f"SQL Injection Detected: {normalized['request_features']['has_sql_injection']}")
    print(f"XSS Detected: {normalized['request_features']['has_xss_attempt']}")
    print(f"Suspicious Pattern Count: {normalized['request_features']['suspicious_patterns']}")
    print("-" * 80)

# Save processed data for later use
with open('processed_logs.json', 'w') as f:
    json.dump(processed_logs, f, indent=2, default=str)

print(f"\nProcessed {len(processed_logs)} log entries")
print("Data saved to 'processed_logs.json'")
# Create the parser and normalizer (Day 1)
parser_script = '''#!/usr/bin/env python3
"""
HTTP Log Parser and Normalizer for WAF ML Training.
Parses Apache log format and applies normalization rules.
"""

import re
import os
import argparse
from typing import Dict, Optional, List

class LogParser:
    """Parse and normalize Apache access logs"""
    
    def __init__(self):
        # Apache Combined Log Format regex
        self.log_pattern = re.compile(
            r'(?P<ip>\\S+) \\S+ \\S+ \\[(?P<timestamp>[^\\]]+)\\] '
            r'"(?P<method>\\S+) (?P<path>\\S+) (?P<protocol>\\S+)" '
            r'(?P<status>\\d+) (?P<size>\\S+) '
            r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
        )
    
    def normalize_path(self, path: str) -> str:
        """
        Apply normalization rules to HTTP paths:
        1. Replace numeric IDs: /user/1234 → /user/<ID>
        2. Replace query parameter values: ?id=123&name=test → ?id=<ID>&name=<VAL>
        3. Replace tokens/hashes: long alphanumeric → <TOKEN>
        4. Replace standalone numbers: <NUM>
        """
        # Split path and query string
        if '?' in path:
            base_path, query_string = path.split('?', 1)
        else:
            base_path, query_string = path, ""
        
        # Normalize base path - replace numeric path segments
        base_path = re.sub(r'/\\d+(?=/|$)', '/<ID>', base_path)
        
        # Normalize query parameters
        if query_string:
            # Replace numeric values
            query_string = re.sub(r'=\\d+(?=&|$)', '=<ID>', query_string)
            # Replace non-numeric values (preserve parameter names)
            query_string = re.sub(r'=([^&\\d][^&]*)', '=<VAL>', query_string)
            path = base_path + '?' + query_string
        else:
            path = base_path
        
        # Replace long alphanumeric tokens (6+ characters)
        path = re.sub(r'\\b[a-zA-Z0-9]{6,}\\b', '<TOKEN>', path)
        
        # Replace remaining standalone numbers
        path = re.sub(r'\\b\\d+\\b', '<NUM>', path)
        
        return path
    
    def parse_log_line(self, line: str) -> Optional[Dict]:
        """Parse a single Apache log line"""
        line = line.strip()
        if not line:
            return None
        
        match = self.log_pattern.match(line)
        if not match:
            return None
        
        parsed = match.groupdict()
        
        # Normalize the path
        parsed['normalized_path'] = self.normalize_path(parsed['path'])
        
        return parsed
    
    def create_sequence(self, parsed_log: Dict) -> str:
        """Create normalized sequence for ML training"""
        method = parsed_log['method']
        normalized_path = parsed_log['normalized_path']
        return f"{method} {normalized_path}"
    
    def process_log_file(self, input_file: str, output_file: str) -> Dict:
        """Process entire log file and create normalized sequences"""
        
        print(f"Processing log file: {input_file}")
        
        sequences = []
        processed_count = 0
        error_count = 0
        
        with open(input_file, 'r') as infile:
            for line_num, line in enumerate(infile, 1):
                try:
                    parsed = self.parse_log_line(line)
                    if parsed:
                        sequence = self.create_sequence(parsed)
                        sequences.append(sequence)
                        processed_count += 1
                    else:
                        error_count += 1
                except Exception as e:
                    print(f"Error processing line {line_num}: {e}")
                    error_count += 1
                
                if line_num % 1000 == 0:
                    print(f"Processed {line_num} lines...")
        
        # Write normalized sequences
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w') as outfile:
            for sequence in sequences:
                outfile.write(sequence + '\\n')
        
        # Statistics
        unique_patterns = set(sequences)
        stats = {
            'total_lines': line_num,
            'processed_count': processed_count,
            'error_count': error_count,
            'unique_patterns': len(unique_patterns),
            'compression_ratio': f"{processed_count}:{len(unique_patterns)}"
        }
        
        print(f"✅ Processed {processed_count} log entries")
        print(f"✅ Found {len(unique_patterns)} unique patterns")
        print(f"✅ Compression ratio: {stats['compression_ratio']}")
        print(f"✅ Output saved to: {output_file}")
        
        return stats

def main():
    parser = argparse.ArgumentParser(description="Parse and normalize Apache access logs")
    parser.add_argument("--input", required=True, help="Input log file path")
    parser.add_argument("--output", default="data/normalized.txt", 
                       help="Output file for normalized sequences")
    parser.add_argument("--verbose", "-v", action="store_true", 
                       help="Enable verbose output")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.input):
        print(f"Error: Input file '{args.input}' not found")
        return 1
    
    log_parser = LogParser()
    stats = log_parser.process_log_file(args.input, args.output)
    
    if args.verbose:
        print("\\n📊 Processing Statistics:")
        for key, value in stats.items():
            print(f"  {key}: {value}")

if __name__ == "__main__":
    exit(main())
'''

with open("webapp-ml-waf/src/parser.py", "w") as f:
    f.write(parser_script)

print("✅ Created log parser script")
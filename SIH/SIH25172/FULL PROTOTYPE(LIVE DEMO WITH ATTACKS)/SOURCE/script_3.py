# Create the log generator script (Day 1)
gen_logs_script = '''#!/usr/bin/env python3
"""
Synthetic HTTP log generator for training WAF ML models.
Generates realistic Apache-format access logs with various endpoints and parameters.
"""

import random
import time
import json
import argparse
import os

# Common web application patterns
PATHS = [
    "/", "/index.html", "/home", "/about", "/contact",
    "/login", "/logout", "/register", "/profile", "/dashboard",
    "/api/users", "/api/items", "/api/orders", "/api/products",
    "/api/item/{}", "/api/user/{}", "/api/order/{}",
    "/search", "/search?q={}", "/category?id={}",
    "/admin", "/admin/users", "/admin/settings",
    "/static/css/style.css", "/static/js/app.js", "/static/images/logo.png",
    "/health", "/status", "/metrics"
]

METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]
METHOD_WEIGHTS = [70, 20, 5, 2, 2, 1]  # GET is most common

STATUS_CODES = [200, 200, 200, 200, 301, 302, 404, 500]
STATUS_WEIGHTS = [80, 5, 5, 5, 2, 2, 1]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15",
    "curl/7.68.0",
    "PostmanRuntime/7.26.8"
]

def generate_ip():
    """Generate realistic IP addresses"""
    return f"10.0.{random.randint(1,255)}.{random.randint(1,255)}"

def generate_id():
    """Generate random ID for path parameters"""
    return random.randint(1000, 9999)

def generate_query():
    """Generate random query parameter values"""
    queries = ["search_term", "product_name", "user_query", "filter_value"]
    return random.choice(queries) + str(random.randint(1, 999))

def normalize_path(path):
    """Apply normalization rules for training data"""
    # Replace numeric IDs with placeholder
    import re
    path = re.sub(r'/\\d+(?=/|$)', '/<ID>', path)
    
    # Handle query parameters
    if '?' in path:
        base_path, query = path.split('?', 1)
        # Replace parameter values
        query = re.sub(r'=\\d+', '=<ID>', query)
        query = re.sub(r'=[^&\\s]+', '=<VAL>', query)
        path = base_path + '?' + query
    
    # Replace remaining numbers
    path = re.sub(r'\\b\\d+\\b', '<NUM>', path)
    
    return path

def generate_log_entry():
    """Generate a single Apache log entry"""
    ip = generate_ip()
    timestamp = time.strftime("%d/%b/%Y:%H:%M:%S +0000", time.gmtime())
    method = random.choices(METHODS, weights=METHOD_WEIGHTS)[0]
    
    # Select and format path
    path_template = random.choice(PATHS)
    if '{}' in path_template:
        if 'q={}' in path_template:
            path = path_template.format(generate_query())
        else:
            path = path_template.format(generate_id())
    else:
        path = path_template
    
    status = random.choices(STATUS_CODES, weights=STATUS_WEIGHTS)[0]
    size = random.randint(100, 10000)
    referer = '"-"'
    user_agent = f'"{random.choice(USER_AGENTS)}"'
    
    # Apache Common Log Format with User-Agent
    log_entry = (
        f'{ip} - - [{timestamp}] '
        f'"{method} {path} HTTP/1.1" {status} {size} '
        f'{referer} {user_agent}'
    )
    
    return log_entry, f"{method} {normalize_path(path)}"

def generate_logs(num_entries=2000, output_file="data/benign_logs.log", 
                 normalized_file="data/normalized.txt"):
    """Generate synthetic logs and normalized sequences"""
    
    # Ensure data directory exists
    os.makedirs("data", exist_ok=True)
    
    print(f"Generating {num_entries} synthetic log entries...")
    
    with open(output_file, "w") as log_file, \\
         open(normalized_file, "w") as norm_file:
        
        for i in range(num_entries):
            log_entry, normalized_seq = generate_log_entry()
            log_file.write(log_entry + "\\n")
            norm_file.write(normalized_seq + "\\n")
            
            if (i + 1) % 500 == 0:
                print(f"Generated {i + 1}/{num_entries} entries")
    
    print(f"✅ Raw logs saved to: {output_file}")
    print(f"✅ Normalized sequences saved to: {normalized_file}")
    
    # Show statistics
    with open(normalized_file, "r") as f:
        sequences = [line.strip() for line in f.readlines()]
    
    unique_patterns = set(sequences)
    print(f"📊 Total sequences: {len(sequences)}")
    print(f"📊 Unique patterns: {len(unique_patterns)}")
    print(f"📊 Compression ratio: {len(sequences)}:{len(unique_patterns)}")
    
    print("\\n🔍 Top 10 most common patterns:")
    from collections import Counter
    pattern_counts = Counter(sequences)
    for pattern, count in pattern_counts.most_common(10):
        print(f"  {pattern} ({count} times)")

def main():
    parser = argparse.ArgumentParser(description="Generate synthetic HTTP logs for WAF training")
    parser.add_argument("--entries", type=int, default=2000, 
                       help="Number of log entries to generate")
    parser.add_argument("--output", default="data/benign_logs.log",
                       help="Output file for raw logs")
    parser.add_argument("--normalized", default="data/normalized.txt",
                       help="Output file for normalized sequences")
    
    args = parser.parse_args()
    
    generate_logs(args.entries, args.output, args.normalized)

if __name__ == "__main__":
    main()
'''

with open("webapp-ml-waf/scripts/gen_logs.py", "w") as f:
    f.write(gen_logs_script)

print("✅ Created log generator script")
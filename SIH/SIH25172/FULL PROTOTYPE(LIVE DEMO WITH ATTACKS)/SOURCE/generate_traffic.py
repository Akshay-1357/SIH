#!/usr/bin/env python3
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

            print(f"\n📊 Traffic Generation Summary:")
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
        print(f"\n💾 Results saved to: {args.output}")

if __name__ == "__main__":
    main()

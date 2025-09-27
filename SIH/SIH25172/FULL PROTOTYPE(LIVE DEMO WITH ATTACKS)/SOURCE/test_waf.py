#!/usr/bin/env python3
"""
Comprehensive test suite for the ML-powered WAF system.
Tests all components: detector, API, integration.
"""

import unittest
import requests
import json
import time
import os
import sys
from concurrent.futures import ThreadPoolExecutor
import subprocess

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

try:
    from detector import HTTPAnomalyDetector
except ImportError:
    print("Warning: Could not import detector module")

class TestAnomalyDetector(unittest.TestCase):
    """Test the core anomaly detection functionality"""

    def setUp(self):
        self.detector = HTTPAnomalyDetector()

        # Basic training data
        self.training_sequences = [
            "GET /", "POST /login", "GET /api/item/<ID>", 
            "POST /api/user/<ID>", "GET /dashboard", 
            "GET /search?q=<VAL>", "POST /logout"
        ]

        self.detector.train(self.training_sequences)

    def test_benign_requests(self):
        """Test that benign requests get low anomaly scores"""
        benign_cases = [
            "GET /",
            "POST /login", 
            "GET /api/item/<ID>",
            "GET /dashboard"
        ]

        for sequence in benign_cases:
            with self.subTest(sequence=sequence):
                score = self.detector.predict_anomaly_score(sequence)
                self.assertLess(score, 0.3, f"Benign request '{sequence}' got high score: {score}")

    def test_malicious_requests(self):
        """Test that malicious requests get high anomaly scores"""
        malicious_cases = [
            "GET /../etc/passwd",
            "POST /admin/delete_user", 
            "GET /search?q=<script>alert(1)</script>",
            "GET /api?id=1 UNION SELECT password FROM users",
            "POST /cmd/exec"
        ]

        for sequence in malicious_cases:
            with self.subTest(sequence=sequence):
                score = self.detector.predict_anomaly_score(sequence)
                self.assertGreater(score, 0.4, f"Malicious request '{sequence}' got low score: {score}")

    def test_incremental_learning(self):
        """Test incremental learning functionality"""
        initial_patterns = len(self.detector.normal_patterns)

        new_sequences = ["GET /new/endpoint", "POST /api/new"]
        self.detector.incremental_train(new_sequences)

        final_patterns = len(self.detector.normal_patterns)
        self.assertGreater(final_patterns, initial_patterns)

    def test_model_persistence(self):
        """Test model save/load functionality"""
        import tempfile

        # Save model
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            model_path = f.name

        try:
            self.detector.save_model(model_path)

            # Create new detector and load model
            new_detector = HTTPAnomalyDetector()
            new_detector.load_model(model_path)

            # Test that loaded model works the same
            test_sequence = "GET /test"
            original_score = self.detector.predict_anomaly_score(test_sequence)
            loaded_score = new_detector.predict_anomaly_score(test_sequence)

            self.assertAlmostEqual(original_score, loaded_score, places=2)

        finally:
            if os.path.exists(model_path):
                os.unlink(model_path)

class TestAPIIntegration(unittest.TestCase):
    """Test the FastAPI ML service integration"""

    @classmethod
    def setUpClass(cls):
        cls.base_url = "http://localhost:8080"

        # Wait for API to be available
        max_retries = 10
        for i in range(max_retries):
            try:
                response = requests.get(f"{cls.base_url}/health", timeout=2)
                if response.status_code == 200:
                    break
            except requests.exceptions.RequestException:
                if i == max_retries - 1:
                    raise unittest.SkipTest("API server not available for testing")
                time.sleep(2)

    def test_health_endpoint(self):
        """Test API health check"""
        response = requests.get(f"{self.base_url}/health")
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["status"], "healthy")
        self.assertTrue(data["model_loaded"])

    def test_single_prediction(self):
        """Test single anomaly prediction endpoint"""
        test_cases = [
            {"seq": "GET /", "expected_anomaly": False},
            {"seq": "GET /../etc/passwd", "expected_anomaly": True}
        ]

        for case in test_cases:
            with self.subTest(sequence=case["seq"]):
                response = requests.post(
                    f"{self.base_url}/score",
                    json={"seq": case["seq"]}
                )

                self.assertEqual(response.status_code, 200)

                data = response.json()
                self.assertIn("score", data)
                self.assertIn("anomalous", data)
                self.assertEqual(data["anomalous"], case["expected_anomaly"])

    def test_batch_prediction(self):
        """Test batch prediction endpoint"""
        sequences = [
            "GET /",
            "POST /login", 
            "GET /../etc/passwd",
            "POST /admin/delete"
        ]

        response = requests.post(
            f"{self.base_url}/batch_predict",
            json={"sequences": sequences}
        )

        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["total_processed"], len(sequences))
        self.assertEqual(len(data["predictions"]), len(sequences))
        self.assertGreater(data["total_anomalies"], 0)  # Should detect some anomalies

    def test_statistics_endpoint(self):
        """Test statistics endpoint"""
        response = requests.get(f"{self.base_url}/stats")
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertIn("model_info", data)
        self.assertIn("performance_stats", data)

class TestPerformance(unittest.TestCase):
    """Test performance characteristics"""

    def setUp(self):
        self.base_url = "http://localhost:8080"

    def test_response_time(self):
        """Test API response time"""
        start_time = time.time()

        response = requests.post(
            f"{self.base_url}/score",
            json={"seq": "GET /test"}
        )

        response_time = time.time() - start_time

        self.assertEqual(response.status_code, 200)
        self.assertLess(response_time, 0.1)  # Should respond within 100ms

    def test_concurrent_requests(self):
        """Test handling concurrent requests"""
        def make_request():
            return requests.post(
                f"{self.base_url}/score",
                json={"seq": "GET /concurrent/test"}
            )

        # Make 10 concurrent requests
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request) for _ in range(10)]

            results = []
            for future in futures:
                try:
                    response = future.result(timeout=5)
                    results.append(response.status_code == 200)
                except Exception as e:
                    results.append(False)

        # All requests should succeed
        success_rate = sum(results) / len(results)
        self.assertGreater(success_rate, 0.8)  # At least 80% success rate

class TestEndToEnd(unittest.TestCase):
    """End-to-end integration tests"""

    def test_attack_detection_flow(self):
        """Test complete attack detection flow"""
        # Test sequences representing different attack types
        attack_scenarios = [
            {
                "name": "SQL Injection",
                "sequence": "GET /api/users?id=1 UNION SELECT password FROM admin",
                "should_detect": True
            },
            {
                "name": "XSS",
                "sequence": "GET /search?q=<script>alert(1)</script>",
                "should_detect": True
            },
            {
                "name": "Directory Traversal", 
                "sequence": "GET /../etc/passwd",
                "should_detect": True
            },
            {
                "name": "Normal Request",
                "sequence": "GET /api/items",
                "should_detect": False
            }
        ]

        for scenario in attack_scenarios:
            with self.subTest(attack=scenario["name"]):
                response = requests.post(
                    "http://localhost:8080/score",
                    json={"seq": scenario["sequence"]}
                )

                self.assertEqual(response.status_code, 200)

                data = response.json()
                detected = data["anomalous"]

                if scenario["should_detect"]:
                    self.assertTrue(detected, f"Failed to detect {scenario['name']}: {scenario['sequence']}")
                    self.assertGreater(data["score"], 0.5)
                else:
                    self.assertFalse(detected, f"False positive for {scenario['name']}: {scenario['sequence']}")

def run_system_tests():
    """Run additional system-level tests"""
    print("\n🔧 Running System Tests...")

    # Test that log files are created
    log_files = ["logs/api.log", "logs/waf_detections.log"]
    for log_file in log_files:
        if os.path.exists(log_file):
            print(f"✅ Log file exists: {log_file}")
        else:
            print(f"⚠️  Log file missing: {log_file}")

    # Test model files
    model_files = ["model/final/detector.json", "data/normalized.txt"]
    for model_file in model_files:
        if os.path.exists(model_file):
            print(f"✅ Model file exists: {model_file}")
        else:
            print(f"⚠️  Model file missing: {model_file}")

if __name__ == "__main__":
    print("🧪 ML-powered WAF Test Suite")
    print("============================")

    # Run system tests first
    run_system_tests()

    # Run unit tests
    print("\n🔍 Running Unit Tests...")

    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add test classes
    test_classes = [TestAnomalyDetector, TestAPIIntegration, TestPerformance, TestEndToEnd]

    for test_class in test_classes:
        tests = loader.loadTestsFromTestClass(test_class)
        suite.addTests(tests)

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Print summary
    print(f"\n📊 Test Summary:")
    print(f"   Tests run: {result.testsRun}")
    print(f"   Failures: {len(result.failures)}")
    print(f"   Errors: {len(result.errors)}")

    if result.failures:
        print("\n❌ Failures:")
        for test, failure in result.failures:
            print(f"   {test}: {failure}")

    if result.errors:
        print("\n💥 Errors:")
        for test, error in result.errors:
            print(f"   {test}: {error}")

    if result.wasSuccessful():
        print("\n🎉 All tests passed! WAF is ready for production.")
        exit(0)
    else:
        print("\n⚠️  Some tests failed. Check the issues above.")
        exit(1)

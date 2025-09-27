#!/usr/bin/env python3
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
    print(f"\n🔄 Performing incremental training...")
    print(f"   New sequences: {len(new_sequences)}")
    print(f"   Epochs: {epochs}")

    for epoch in range(epochs):
        if detector.is_trained:
            stats = detector.incremental_train(new_sequences)
        else:
            stats = detector.train(new_sequences)

        print(f"\n📊 Epoch {epoch + 1}/{epochs} completed:")
        for key, value in stats.items():
            print(f"   {key}: {value}")

    # Save updated model
    detector.save_model(model_path)
    print(f"\n✅ Updated model saved to: {model_path}")

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

    print(f"\n🧪 Validating updated model with {len(test_sequences)} test cases:")
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

        print(f"\n📊 Validation Statistics:")
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

        print(f"\n🎉 Incremental training completed successfully!")

    except Exception as e:
        print(f"❌ Error during incremental training: {e}")
        return 1

    return 0

if __name__ == "__main__":
    exit(main())

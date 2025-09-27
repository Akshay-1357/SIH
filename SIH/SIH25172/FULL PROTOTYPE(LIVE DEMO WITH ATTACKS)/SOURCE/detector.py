#!/usr/bin/env python3
"""
Lightweight ML-based HTTP Anomaly Detector for WAF.
Uses pattern matching and token frequency analysis for fast inference.
"""

import json
import os
import numpy as np
from collections import Counter, defaultdict
from typing import Dict, List, Set, Tuple, Optional
from tokenizers import Tokenizer
import argparse
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class HTTPAnomalyDetector:
    """
    Lightweight anomaly detector for HTTP requests.

    Features:
    - Pattern-based exact matching for known benign requests
    - Token frequency analysis for unknown patterns  
    - Heuristic rules for common attack patterns
    - Configurable threshold and incremental learning
    """

    def __init__(self, config_path: Optional[str] = None):
        self.normal_patterns: Set[str] = set()
        self.token_frequencies: Dict[str, int] = defaultdict(int)
        self.suspicious_patterns = self._load_attack_patterns()
        self.is_trained = False

        # Configuration
        self.config = self._load_config(config_path)
        self.threshold = self.config.get('anomaly_threshold', 0.5)
        self.max_sequence_length = self.config.get('max_sequence_length', 200)

        # Statistics
        self.stats = {
            'total_predictions': 0,
            'anomalies_detected': 0,
            'exact_matches': 0,
            'token_based_detections': 0,
            'rule_based_detections': 0
        }

    def _load_config(self, config_path: Optional[str]) -> Dict:
        """Load configuration from JSON file"""
        default_config = {
            'anomaly_threshold': 0.5,
            'max_sequence_length': 200,
            'enable_token_analysis': True,
            'enable_rule_analysis': True,
            'token_weight': 0.6,
            'rule_weight': 0.4
        }

        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            except Exception as e:
                logger.warning(f"Failed to load config from {config_path}: {e}")

        return default_config

    def _load_attack_patterns(self) -> List[Tuple[str, float]]:
        """Load predefined suspicious patterns with weights"""
        return [
            # SQL Injection patterns
            ('union', 0.8), ('select', 0.7), ('insert', 0.6), ('update', 0.6),
            ('delete', 0.7), ('drop', 0.9), ('create', 0.6), ('alter', 0.6),
            ('exec', 0.8), ('execute', 0.8),

            # XSS patterns
            ('script', 0.7), ('javascript:', 0.8), ('vbscript:', 0.8),
            ('onload', 0.6), ('onerror', 0.6), ('onclick', 0.5),
            ('<script', 0.9), ('</script', 0.9), ('alert(', 0.7),

            # Directory traversal
            ('../', 0.8), ('../', 0.8), ('/./', 0.6), ('/etc/', 0.7),
            ('/passwd', 0.9), ('/shadow', 0.9), ('/proc/', 0.6),

            # Admin/sensitive paths
            ('admin', 0.4), ('administrator', 0.5), ('root', 0.5),
            ('config', 0.4), ('backup', 0.4), ('phpinfo', 0.6),

            # Command injection
            ('cmd', 0.6), ('command', 0.6), ('shell', 0.6), ('bash', 0.7),
            ('system', 0.6), ('eval', 0.7), ('passthru', 0.7),

            # File inclusion
            ('include', 0.5), ('require', 0.5), ('file', 0.4),
            ('download', 0.4), ('upload', 0.4),

            # Buffer overflow indicators
            ('A' * 50, 0.6),  # Long repetitive strings
            ('0' * 50, 0.6),  # Long numeric strings
        ]

    def train(self, sequences: List[str]) -> Dict:
        """Train the detector on benign sequences"""
        logger.info(f"Training on {len(sequences)} benign sequences...")

        self.normal_patterns.clear()
        self.token_frequencies.clear()

        for sequence in sequences:
            sequence = sequence.strip()
            if not sequence:
                continue

            # Add to normal patterns
            self.normal_patterns.add(sequence)

            # Token frequency analysis
            tokens = self._tokenize_sequence(sequence)
            for token in tokens:
                self.token_frequencies[token] += 1

        self.is_trained = True

        # Generate training statistics
        unique_tokens = len(self.token_frequencies)
        unique_patterns = len(self.normal_patterns)

        training_stats = {
            'total_sequences': len(sequences),
            'unique_patterns': unique_patterns,
            'unique_tokens': unique_tokens,
            'compression_ratio': f"{len(sequences)}:{unique_patterns}",
            'avg_tokens_per_sequence': np.mean([len(self._tokenize_sequence(s)) for s in sequences[:100]])
        }

        logger.info(f"✅ Training completed:")
        logger.info(f"   - Unique patterns: {unique_patterns}")
        logger.info(f"   - Token vocabulary: {unique_tokens}")
        logger.info(f"   - Compression ratio: {training_stats['compression_ratio']}")

        return training_stats

    def _tokenize_sequence(self, sequence: str) -> List[str]:
        """Simple tokenization by splitting on whitespace and special characters"""
        # Split on whitespace and common HTTP delimiters
        import re
        tokens = re.split(r'[\s/\?&=<>]+', sequence.lower())
        return [token for token in tokens if token]

    def predict_anomaly_score(self, sequence: str) -> float:
        """
        Predict anomaly score for a sequence (0.0 = normal, 1.0 = highly anomalous)
        """
        if not self.is_trained:
            logger.warning("Detector not trained, returning high anomaly score")
            return 1.0

        sequence = sequence.strip()
        if not sequence:
            return 0.0

        # Update statistics
        self.stats['total_predictions'] += 1

        # 1. Exact pattern matching (lowest score)
        if sequence in self.normal_patterns:
            self.stats['exact_matches'] += 1
            return 0.0

        # 2. Token frequency analysis
        token_score = 0.0
        if self.config.get('enable_token_analysis', True):
            token_score = self._calculate_token_score(sequence)

        # 3. Rule-based suspicious pattern detection
        rule_score = 0.0
        if self.config.get('enable_rule_analysis', True):
            rule_score = self._calculate_rule_score(sequence)

        # 4. Length-based anomaly detection
        length_penalty = min(0.3, max(0.0, (len(sequence) - self.max_sequence_length) / 500))

        # Combine scores
        token_weight = self.config.get('token_weight', 0.6)
        rule_weight = self.config.get('rule_weight', 0.4)

        final_score = min(1.0, token_score * token_weight + rule_score * rule_weight + length_penalty)

        return final_score

    def _calculate_token_score(self, sequence: str) -> float:
        """Calculate anomaly score based on token frequencies"""
        tokens = self._tokenize_sequence(sequence)
        if not tokens:
            return 1.0

        max_frequency = max(self.token_frequencies.values()) if self.token_frequencies else 1
        token_scores = []

        for token in tokens:
            if token in self.token_frequencies:
                # Normalize frequency score (higher frequency = lower anomaly)
                frequency_score = 1.0 - (self.token_frequencies[token] / max_frequency)
            else:
                # Unknown token gets high anomaly score
                frequency_score = 0.8

            token_scores.append(frequency_score)

        if token_scores:
            self.stats['token_based_detections'] += 1

        return np.mean(token_scores)

    def _calculate_rule_score(self, sequence: str) -> float:
        """Calculate anomaly score based on suspicious pattern rules"""
        sequence_lower = sequence.lower()
        rule_scores = []

        for pattern, weight in self.suspicious_patterns:
            if pattern.lower() in sequence_lower:
                rule_scores.append(weight)

        if rule_scores:
            self.stats['rule_based_detections'] += 1
            return min(1.0, np.max(rule_scores))  # Take highest matching rule score

        return 0.0

    def is_anomaly(self, sequence: str) -> bool:
        """Binary anomaly classification"""
        score = self.predict_anomaly_score(sequence)
        is_anomalous = score > self.threshold

        if is_anomalous:
            self.stats['anomalies_detected'] += 1

        return is_anomalous

    def get_prediction_details(self, sequence: str) -> Dict:
        """Get detailed prediction information"""
        token_score = self._calculate_token_score(sequence)
        rule_score = self._calculate_rule_score(sequence)
        final_score = self.predict_anomaly_score(sequence)

        # Determine confidence level
        if final_score < 0.2:
            confidence = "very_low"
        elif final_score < 0.4:
            confidence = "low"
        elif final_score < 0.6:
            confidence = "medium"
        elif final_score < 0.8:
            confidence = "high"
        else:
            confidence = "very_high"

        return {
            'sequence': sequence,
            'anomaly_score': round(final_score, 3),
            'is_anomaly': final_score > self.threshold,
            'confidence': confidence,
            'token_score': round(token_score, 3),
            'rule_score': round(rule_score, 3),
            'exact_match': sequence in self.normal_patterns,
            'details': {
                'tokens': self._tokenize_sequence(sequence),
                'length': len(sequence),
                'threshold': self.threshold
            }
        }

    def update_threshold(self, new_threshold: float):
        """Update anomaly detection threshold"""
        if 0.0 <= new_threshold <= 1.0:
            self.threshold = new_threshold
            logger.info(f"Threshold updated to: {new_threshold}")
        else:
            raise ValueError("Threshold must be between 0.0 and 1.0")

    def incremental_train(self, new_sequences: List[str]) -> Dict:
        """Add new benign sequences to the model"""
        if not self.is_trained:
            return self.train(new_sequences)

        initial_patterns = len(self.normal_patterns)
        initial_tokens = len(self.token_frequencies)

        for sequence in new_sequences:
            sequence = sequence.strip()
            if sequence:
                self.normal_patterns.add(sequence)
                tokens = self._tokenize_sequence(sequence)
                for token in tokens:
                    self.token_frequencies[token] += 1

        new_patterns = len(self.normal_patterns) - initial_patterns
        new_tokens = len(self.token_frequencies) - initial_tokens

        update_stats = {
            'new_patterns_added': new_patterns,
            'new_tokens_added': new_tokens,
            'total_patterns': len(self.normal_patterns),
            'total_tokens': len(self.token_frequencies)
        }

        logger.info(f"✅ Incremental training completed:")
        logger.info(f"   - New patterns added: {new_patterns}")
        logger.info(f"   - Total patterns: {len(self.normal_patterns)}")

        return update_stats

    def get_statistics(self) -> Dict:
        """Get detector performance statistics"""
        total_predictions = self.stats['total_predictions']
        if total_predictions > 0:
            anomaly_rate = (self.stats['anomalies_detected'] / total_predictions) * 100
            exact_match_rate = (self.stats['exact_matches'] / total_predictions) * 100
        else:
            anomaly_rate = 0
            exact_match_rate = 0

        return {
            **self.stats,
            'anomaly_rate_percent': round(anomaly_rate, 2),
            'exact_match_rate_percent': round(exact_match_rate, 2),
            'model_info': {
                'is_trained': self.is_trained,
                'normal_patterns_count': len(self.normal_patterns),
                'token_vocabulary_size': len(self.token_frequencies),
                'threshold': self.threshold
            }
        }

    def save_model(self, model_path: str):
        """Save trained model to disk"""
        os.makedirs(os.path.dirname(model_path), exist_ok=True)

        model_data = {
            'normal_patterns': list(self.normal_patterns),
            'token_frequencies': dict(self.token_frequencies),
            'config': self.config,
            'stats': self.stats,
            'is_trained': self.is_trained
        }

        with open(model_path, 'w') as f:
            json.dump(model_data, f, indent=2)

        logger.info(f"✅ Model saved to: {model_path}")

    def load_model(self, model_path: str):
        """Load trained model from disk"""
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model file not found: {model_path}")

        with open(model_path, 'r') as f:
            model_data = json.load(f)

        self.normal_patterns = set(model_data.get('normal_patterns', []))
        self.token_frequencies = defaultdict(int, model_data.get('token_frequencies', {}))
        self.config.update(model_data.get('config', {}))
        self.stats = model_data.get('stats', self.stats)
        self.is_trained = model_data.get('is_trained', False)
        self.threshold = self.config.get('anomaly_threshold', 0.5)

        logger.info(f"✅ Model loaded from: {model_path}")
        logger.info(f"   - Patterns: {len(self.normal_patterns)}")
        logger.info(f"   - Token vocabulary: {len(self.token_frequencies)}")

def main():
    parser = argparse.ArgumentParser(description="Train HTTP Anomaly Detector")
    parser.add_argument("--train", help="Training data file (normalized sequences)")
    parser.add_argument("--test", help="Test sequences file")
    parser.add_argument("--model", default="model/final/detector.json", 
                       help="Model save/load path")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--threshold", type=float, help="Anomaly detection threshold")

    args = parser.parse_args()

    # Initialize detector
    detector = HTTPAnomalyDetector(args.config)

    if args.threshold:
        detector.update_threshold(args.threshold)

    # Training
    if args.train:
        if not os.path.exists(args.train):
            print(f"Error: Training file '{args.train}' not found")
            return 1

        with open(args.train, 'r') as f:
            sequences = [line.strip() for line in f.readlines() if line.strip()]

        stats = detector.train(sequences)
        detector.save_model(args.model)

        print("\n📊 Training Statistics:")
        for key, value in stats.items():
            print(f"  {key}: {value}")

    # Testing
    if args.test:
        if not detector.is_trained:
            if os.path.exists(args.model):
                detector.load_model(args.model)
            else:
                print("Error: No trained model found. Train first or provide model file.")
                return 1

        # Test cases
        test_cases = []
        if os.path.exists(args.test):
            with open(args.test, 'r') as f:
                test_cases = [line.strip() for line in f.readlines() if line.strip()]
        else:
            # Default test cases
            test_cases = [
                "GET /login",
                "POST /api/item/<ID>",
                "GET /../etc/passwd",
                "POST /admin/delete",
                "GET /search?q=<script>alert(1)</script>",
                "GET /api?id=1 UNION SELECT password FROM users"
            ]

        print("\n🔍 Testing Anomaly Detection:")
        print("=" * 60)

        for sequence in test_cases:
            details = detector.get_prediction_details(sequence)
            status = "🚨 ANOMALY" if details['is_anomaly'] else "✅ NORMAL"
            print(f"{status} | Score: {details['anomaly_score']:.3f} | {sequence}")

        # Show statistics
        stats = detector.get_statistics()
        print("\n📊 Detection Statistics:")
        for key, value in stats.items():
            if not isinstance(value, dict):
                print(f"  {key}: {value}")

if __name__ == "__main__":
    exit(main())

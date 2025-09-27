# Fix the syntax error and create the real-time WAF engine
from datetime import datetime, timedelta
import json
import re
import threading
import time
import queue
import csv
from collections import deque
import sqlite3
import uuid

class WAFRealTimeEngine:
    """Real-time Web Application Firewall processing engine"""
    
    def __init__(self, max_buffer_size=10000):
        self.request_buffer = deque(maxlen=max_buffer_size)
        self.threat_buffer = deque(maxlen=1000)
        self.processing_queue = queue.Queue()
        self.is_running = False
        
        # Initialize SQLite database for logging
        self.init_database()
        
        # Detection model
        self.waf_model = WAFModelDemo()
        
        # Performance metrics
        self.metrics = {
            'requests_processed': 0,
            'threats_detected': 0,
            'false_positives': 0,
            'average_response_time': 0.0,
            'uptime_start': datetime.now()
        }
        
        # Threat patterns for incremental learning
        self.learned_patterns = set()
        self.pattern_frequency = {}
        
    def init_database(self):
        """Initialize SQLite database for logging"""
        self.conn = sqlite3.connect('waf_logs.db', check_same_thread=False)
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS requests (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                client_ip TEXT,
                method TEXT,
                url TEXT,
                user_agent TEXT,
                status_code INTEGER,
                risk_score REAL,
                risk_level TEXT,
                is_blocked BOOLEAN,
                threats TEXT,
                response_time_ms REAL
            )
        ''')
        
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS threat_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern TEXT UNIQUE,
                threat_type TEXT,
                frequency INTEGER DEFAULT 1,
                first_seen TEXT,
                last_seen TEXT
            )
        ''')
        self.conn.commit()
    
    def start_processing(self):
        """Start the real-time processing engine"""
        self.is_running = True
        self.processing_thread = threading.Thread(target=self._process_requests)
        self.processing_thread.daemon = True
        self.processing_thread.start()
        print("🚀 WAF Real-time Engine started")
    
    def stop_processing(self):
        """Stop the real-time processing engine"""
        self.is_running = False
        print("⏹️  WAF Real-time Engine stopped")
    
    def _process_requests(self):
        """Main processing loop for incoming requests"""
        while self.is_running:
            try:
                if not self.processing_queue.empty():
                    request_data = self.processing_queue.get(timeout=0.1)
                    self._analyze_request(request_data)
                else:
                    time.sleep(0.001)  # Small delay to prevent busy waiting
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Error processing request: {e}")
    
    def ingest_request(self, log_line):
        """Ingest a new request for real-time analysis"""
        start_time = time.time()
        
        try:
            # Parse log entry
            log_entry = LogEntry(log_line)
            
            request_data = {
                'id': str(uuid.uuid4()),
                'timestamp': datetime.now().isoformat(),
                'log_entry': log_entry,
                'raw_log': log_line,
                'start_time': start_time
            }
            
            # Add to processing queue
            self.processing_queue.put(request_data)
            
            # Add to buffer for monitoring
            self.request_buffer.append(request_data)
            
            return request_data['id']
            
        except Exception as e:
            print(f"Error ingesting request: {e}")
            return None
    
    def _analyze_request(self, request_data):
        """Analyze a single request for threats"""
        try:
            log_entry = request_data['log_entry']
            
            # Perform threat analysis
            analysis = self.waf_model.analyze_request(
                {'parsed': log_entry.parsed_data}, 
                request_data['raw_log']
            )
            
            # Calculate response time
            response_time = (time.time() - request_data['start_time']) * 1000  # ms
            
            # Update metrics
            self.metrics['requests_processed'] += 1
            self.metrics['average_response_time'] = (
                (self.metrics['average_response_time'] * (self.metrics['requests_processed'] - 1) + response_time) /
                self.metrics['requests_processed']
            )
            
            if analysis['is_anomaly']:
                self.metrics['threats_detected'] += 1
                
                # Add to threat buffer
                threat_info = {
                    'id': request_data['id'],
                    'timestamp': request_data['timestamp'],
                    'client_ip': log_entry.parsed_data.get('client_ip', 'unknown'),
                    'method': log_entry.parsed_data.get('method', 'unknown'),
                    'url': log_entry.parsed_data.get('url', 'unknown'),
                    'risk_score': analysis['risk_score'],
                    'risk_level': analysis['risk_level'],
                    'threats': analysis['threats_detected']
                }
                self.threat_buffer.append(threat_info)
                
                # Learn from new threat patterns
                self._update_threat_patterns(analysis['threats_detected'], request_data['raw_log'])
            
            # Store in database
            self._store_request(request_data, log_entry, analysis, response_time)
            
        except Exception as e:
            print(f"Error analyzing request {request_data.get('id', 'unknown')}: {e}")
    
    def _update_threat_patterns(self, threats, request_text):
        """Update threat patterns for incremental learning"""
        for threat_type in threats:
            # Extract potential patterns from request
            patterns = self._extract_patterns(request_text, threat_type)
            
            for pattern in patterns:
                if pattern not in self.learned_patterns:
                    self.learned_patterns.add(pattern)
                    self.pattern_frequency[pattern] = 1
                    
                    # Store in database
                    try:
                        self.conn.execute(
                            'INSERT OR IGNORE INTO threat_patterns (pattern, threat_type, first_seen, last_seen) VALUES (?, ?, ?, ?)',
                            (pattern, threat_type, datetime.now().isoformat(), datetime.now().isoformat())
                        )
                        self.conn.commit()
                    except:
                        pass
                else:
                    self.pattern_frequency[pattern] += 1
                    
                    # Update database
                    try:
                        self.conn.execute(
                            'UPDATE threat_patterns SET frequency = frequency + 1, last_seen = ? WHERE pattern = ?',
                            (datetime.now().isoformat(), pattern)
                        )
                        self.conn.commit()
                    except:
                        pass
    
    def _extract_patterns(self, request_text, threat_type):
        """Extract learnable patterns from request text"""
        patterns = []
        request_lower = request_text.lower()
        
        if threat_type == 'sql_injection':
            # Extract SQL injection patterns
            sql_keywords = ['union', 'select', 'drop', 'insert', 'delete', 'update']
            for keyword in sql_keywords:
                if keyword in request_lower:
                    # Extract surrounding context
                    idx = request_lower.find(keyword)
                    start = max(0, idx - 10)
                    end = min(len(request_text), idx + len(keyword) + 10)
                    context = request_text[start:end]
                    patterns.append(context)
        
        elif threat_type == 'xss':
            # Extract XSS patterns
            if '<script>' in request_lower:
                patterns.append('<script>')
            if 'javascript:' in request_lower:
                patterns.append('javascript:')
        
        elif threat_type == 'path_traversal':
            # Extract path traversal patterns
            if '../' in request_text:
                patterns.append('../')
            if '..\\\' in request_text:
                patterns.append('..\\')
        
        return patterns[:5]  # Limit to 5 patterns per request
    
    def _store_request(self, request_data, log_entry, analysis, response_time):
        """Store request data in database"""
        try:
            self.conn.execute('''
                INSERT INTO requests 
                (id, timestamp, client_ip, method, url, user_agent, status_code, 
                 risk_score, risk_level, is_blocked, threats, response_time_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                request_data['id'],
                request_data['timestamp'],
                log_entry.parsed_data.get('client_ip', ''),
                log_entry.parsed_data.get('method', ''),
                log_entry.parsed_data.get('url', ''),
                log_entry.parsed_data.get('user_agent', '')[:200],  # Truncate long user agents
                log_entry.parsed_data.get('status_code', 0),
                analysis['risk_score'],
                analysis['risk_level'],
                analysis['is_anomaly'],
                ','.join(analysis['threats_detected']),
                response_time
            ))
            self.conn.commit()
        except Exception as e:
            print(f"Database error: {e}")
    
    def get_real_time_stats(self):
        """Get real-time statistics"""
        uptime = datetime.now() - self.metrics['uptime_start']
        
        return {
            'uptime_seconds': int(uptime.total_seconds()),
            'requests_processed': self.metrics['requests_processed'],
            'threats_detected': self.metrics['threats_detected'],
            'detection_rate': round((self.metrics['threats_detected'] / max(1, self.metrics['requests_processed'])) * 100, 2),
            'average_response_time_ms': round(self.metrics['average_response_time'], 2),
            'requests_in_buffer': len(self.request_buffer),
            'threats_in_buffer': len(self.threat_buffer),
            'learned_patterns': len(self.learned_patterns),
            'queue_size': self.processing_queue.qsize()
        }
    
    def get_recent_threats(self, limit=10):
        """Get recent threat detections"""
        return list(self.threat_buffer)[-limit:]
    
    def get_top_threat_patterns(self, limit=10):
        """Get most frequent threat patterns"""
        sorted_patterns = sorted(
            self.pattern_frequency.items(), 
            key=lambda x: x[1], 
            reverse=True
        )
        return sorted_patterns[:limit]

# Initialize and test the real-time engine
print("=== WAF Real-time Processing Engine ===\n")

# Create engine
waf_engine = WAFRealTimeEngine()

# Start processing
waf_engine.start_processing()

# Test logs for real-time processing
test_logs_realtime = [
    '192.168.1.100 - - [26/Sep/2025:19:15:36 +0000] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
    '10.0.0.1 - - [26/Sep/2025:19:16:15 +0000] "POST /api/login HTTP/1.1" 200 1547 "-" "curl/7.64.1"',
    '192.168.1.50 - - [26/Sep/2025:19:16:45 +0000] "GET /admin/users.php?id=1 UNION SELECT password FROM admin-- HTTP/1.1" 403 0 "-" "sqlmap/1.4.7"',
    '10.0.0.2 - - [26/Sep/2025:19:17:12 +0000] "GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1" 200 3421 "-" "Mozilla/5.0 (compatible; bot)"',
    '192.168.1.100 - - [26/Sep/2025:19:17:30 +0000] "GET /contact HTTP/1.1" 200 1456 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"',
    '10.0.0.3 - - [26/Sep/2025:19:18:05 +0000] "GET /file.php?path=../../../etc/passwd HTTP/1.1" 500 0 "-" "python-requests/2.25.1"'
]

print("Ingesting real-time requests:")

# Process requests with small delays
request_ids = []
for i, log in enumerate(test_logs_realtime):
    request_id = waf_engine.ingest_request(log)
    request_ids.append(request_id)
    print(f"  📨 Request {i+1} ingested: {request_id}")
    time.sleep(0.1)  # Simulate real-time ingestion

# Wait for processing to complete
time.sleep(0.5)

# Get real-time statistics
stats = waf_engine.get_real_time_stats()
print(f"\n📊 Real-time Statistics:")
for key, value in stats.items():
    print(f"   {key.replace('_', ' ').title()}: {value}")

# Get recent threats
recent_threats = waf_engine.get_recent_threats(5)
print(f"\n🚨 Recent Threats Detected:")
if recent_threats:
    for threat in recent_threats:
        print(f"   {threat['timestamp'][:19]} - {threat['risk_level']} - {threat['method']} {threat['url']}")
        print(f"      Risk Score: {threat['risk_score']:.3f} | Threats: {', '.join(threat['threats'])}")
else:
    print("   No threats detected")

# Get learned patterns
patterns = waf_engine.get_top_threat_patterns(5)
print(f"\n🧠 Learned Threat Patterns:")
if patterns:
    for pattern, frequency in patterns:
        print(f"   '{pattern}' - Seen {frequency} times")
else:
    print("   No patterns learned yet")

# Export recent data to CSV
print(f"\n📄 Exporting data...")

# Get data from database
cursor = waf_engine.conn.cursor()
cursor.execute('SELECT * FROM requests ORDER BY timestamp DESC LIMIT 100')
rows = cursor.fetchall()

if rows:
    with open('waf_realtime_requests.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['ID', 'Timestamp', 'Client_IP', 'Method', 'URL', 'User_Agent', 
                        'Status_Code', 'Risk_Score', 'Risk_Level', 'Is_Blocked', 'Threats', 'Response_Time_MS'])
        writer.writerows(rows)
    print(f"   ✅ Request data exported to 'waf_realtime_requests.csv'")

# Create a summary report
report_data = {
    'timestamp': datetime.now().isoformat(),
    'engine_stats': stats,
    'recent_threats': [dict(threat) for threat in recent_threats],
    'learned_patterns': dict(patterns),
    'total_database_entries': len(rows) if rows else 0
}

with open('waf_realtime_report.json', 'w') as f:
    json.dump(report_data, f, indent=2, default=str)

# Stop the engine
waf_engine.stop_processing()

# Final summary
print(f"\n✨ Real-time Processing Complete!")
print(f"   Processed {stats['requests_processed']} requests")
print(f"   Detected {stats['threats_detected']} threats")
print(f"   Average response time: {stats['average_response_time_ms']:.2f}ms")
print(f"   Detection rate: {stats['detection_rate']}%")
print(f"   Database entries: {len(rows) if rows else 0}")
print(f"   Report saved: waf_realtime_report.json")
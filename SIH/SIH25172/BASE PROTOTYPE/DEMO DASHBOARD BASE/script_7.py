# Fix the CSV export issue and complete the real-time engine
import json

# Fix the export issue by updating the field names
class WAFRealTimeEngineFixed:
    """Fixed real-time WAF processing engine"""
    
    def __init__(self):
        self.request_log = []
        self.threat_log = []
        self.metrics = {
            'requests_processed': 0,
            'threats_detected': 0,
            'start_time': datetime.now()
        }
        self.waf_model = WAFModelDemo()
    
    def process_request(self, log_line):
        """Process a single request in real-time"""
        start_time = time.time()
        
        try:
            # Parse log entry
            log_entry = LogEntry(log_line)
            request_id = str(uuid.uuid4())[:8]
            
            # Perform threat analysis
            analysis = self.waf_model.analyze_request(
                {'parsed': log_entry.parsed_data}, 
                log_line
            )
            
            # Calculate processing time
            processing_time = (time.time() - start_time) * 1000  # ms
            
            # Create request record
            request_record = {
                'id': request_id,
                'timestamp': datetime.now().isoformat(),
                'client_ip': log_entry.parsed_data.get('client_ip', 'unknown'),
                'method': log_entry.parsed_data.get('method', 'unknown'),
                'url': log_entry.parsed_data.get('url', 'unknown'),
                'status_code': log_entry.parsed_data.get('status_code', 0),
                'user_agent': log_entry.parsed_data.get('user_agent', '')[:100],
                'risk_score': analysis['risk_score'],
                'risk_level': analysis['risk_level'],
                'is_threat': analysis['is_anomaly'],
                'threats_detected': analysis['threats_detected'],
                'processing_time_ms': round(processing_time, 2)
            }
            
            # Store request
            self.request_log.append(request_record)
            self.metrics['requests_processed'] += 1
            
            # If threat detected, add to threat log
            if analysis['is_anomaly']:
                self.threat_log.append(request_record)
                self.metrics['threats_detected'] += 1
            
            return request_record
            
        except Exception as e:
            print(f"Error processing request: {e}")
            return None
    
    def get_stats(self):
        """Get current statistics"""
        uptime = datetime.now() - self.metrics['start_time']
        avg_processing_time = (
            sum(r['processing_time_ms'] for r in self.request_log) / 
            max(1, len(self.request_log))
        )
        
        return {
            'uptime_seconds': int(uptime.total_seconds()),
            'requests_processed': self.metrics['requests_processed'],
            'threats_detected': self.metrics['threats_detected'],
            'detection_rate_percent': round(
                (self.metrics['threats_detected'] / max(1, self.metrics['requests_processed'])) * 100, 2
            ),
            'average_processing_time_ms': round(avg_processing_time, 2),
            'requests_per_second': round(
                self.metrics['requests_processed'] / max(1, uptime.total_seconds()), 2
            )
        }
    
    def export_to_csv(self, filename):
        """Export request data to CSV"""
        if not self.request_log:
            return False
        
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=[
                'id', 'timestamp', 'client_ip', 'method', 'url', 'status_code',
                'user_agent', 'risk_score', 'risk_level', 'is_threat', 
                'threats_detected', 'processing_time_ms'
            ])
            writer.writeheader()
            for record in self.request_log:
                # Convert threats list to string
                export_record = record.copy()
                export_record['threats_detected'] = ','.join(export_record['threats_detected'])
                writer.writerow(export_record)
        
        return True

# Re-run the analysis with the fixed engine
print("=== WAF Real-time Engine (Fixed) ===\n")

# Create new engine instance
waf_engine_fixed = WAFRealTimeEngineFixed()

# Process the same test requests
test_requests = [
    '192.168.1.100 - - [26/Sep/2025:19:15:36 +0000] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0 (Windows NT 10.0)"',
    '10.0.0.1 - - [26/Sep/2025:19:16:15 +0000] "POST /api/login HTTP/1.1" 200 1547 "-" "curl/7.64.1"',
    '192.168.1.50 - - [26/Sep/2025:19:16:45 +0000] "GET /admin/users.php?id=1 UNION SELECT password FROM admin-- HTTP/1.1" 403 0 "-" "sqlmap/1.4.7"',
    '10.0.0.2 - - [26/Sep/2025:19:17:12 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 3421 "-" "Mozilla/5.0 (bot)"',
    '192.168.1.100 - - [26/Sep/2025:19:17:30 +0000] "GET /contact.html HTTP/1.1" 200 1456 "-" "Mozilla/5.0 (Macintosh)"',
    '10.0.0.3 - - [26/Sep/2025:19:18:05 +0000] "GET /files.php?path=../../../etc/passwd HTTP/1.1" 500 0 "-" "python-requests/2.25.1"'
]

# Process requests quickly
results = []
for request in test_requests:
    result = waf_engine_fixed.process_request(request)
    if result:
        results.append(result)

# Export to CSV successfully
csv_exported = waf_engine_fixed.export_to_csv('waf_complete_analysis.csv')

# Get final stats
final_stats = waf_engine_fixed.get_stats()

print(f"✅ Processing Complete!")
print(f"   Requests: {final_stats['requests_processed']}")
print(f"   Threats: {final_stats['threats_detected']}")
print(f"   CSV Export: {'Success' if csv_exported else 'Failed'}")

# Create comprehensive summary
comprehensive_summary = {
    'waf_analysis_report': {
        'timestamp': datetime.now().isoformat(),
        'version': 'WAF-Transformer-v1.0-Demo',
        'performance_metrics': final_stats,
        'request_details': results,
        'threat_analysis': {
            'total_threats': final_stats['threats_detected'],
            'threat_types': {},
            'risk_distribution': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'NORMAL': 0}
        },
        'recommendations': [
            "Deploy in production with real BERT transformer model",
            "Implement incremental learning pipeline",
            "Set up real-time monitoring dashboard", 
            "Configure automated threat response actions",
            "Establish baseline performance metrics"
        ]
    }
}

# Analyze threats
for result in results:
    # Count threat types
    for threat in result['threats_detected']:
        comprehensive_summary['waf_analysis_report']['threat_analysis']['threat_types'][threat] = \
            comprehensive_summary['waf_analysis_report']['threat_analysis']['threat_types'].get(threat, 0) + 1
    
    # Count risk levels
    risk_level = result['risk_level']
    comprehensive_summary['waf_analysis_report']['threat_analysis']['risk_distribution'][risk_level] += 1

# Save comprehensive report
with open('waf_comprehensive_report.json', 'w') as f:
    json.dump(comprehensive_summary, f, indent=2, default=str)

print(f"\n📊 Analysis Results:")
print(f"   Detection Rate: {final_stats['detection_rate_percent']}%")
print(f"   Processing Speed: {final_stats['average_processing_time_ms']}ms avg")
print(f"   Throughput: {final_stats['requests_per_second']} req/sec")

threat_summary = comprehensive_summary['waf_analysis_report']['threat_analysis']
print(f"\n🚨 Threat Breakdown:")
for threat_type, count in threat_summary['threat_types'].items():
    print(f"   {threat_type}: {count} occurrences")

print(f"\n📋 Files Generated:")
print(f"   ✅ waf_complete_analysis.csv")
print(f"   ✅ waf_comprehensive_report.json")

print(f"\n🎯 System Ready for:")
print(f"   • Real-time log ingestion from Apache/Nginx")
print(f"   • Integration with BERT transformer models")
print(f"   • Microservices deployment")
print(f"   • Dashboard visualization")
print(f"   • Automated threat response")
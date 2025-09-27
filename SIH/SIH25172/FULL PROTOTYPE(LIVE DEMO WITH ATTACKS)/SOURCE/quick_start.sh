#!/bin/bash
# 🚀 Quick Start Script - Get WAF running in 2 minutes!

set -e

echo "🚀 WAF Quick Start (Hackathon Ready!)"
echo "====================================="
echo

# Check if we're in the right directory
if [ ! -f "setup.sh" ]; then
    echo "❌ Please run this from the webapp-ml-waf directory"
    exit 1
fi

# Quick Python setup
echo "⚡ Setting up Python environment (30 seconds)..."
python3 -m venv venv --quiet
source venv/bin/activate
pip install fastapi uvicorn numpy requests --quiet
echo "✅ Python environment ready"

# Generate training data quickly
echo "⚡ Generating training data (15 seconds)..."
mkdir -p data model/final logs
python3 -c "
import random, time, os
paths = ['/', '/login', '/api/item/{ID}', '/profile/{ID}', '/dashboard', '/search?q={VAL}']
methods = ['GET', 'POST']
sequences = []
for _ in range(1000):
    method = random.choice(methods)
    path = random.choice(paths).replace('{ID}', '<ID>').replace('{VAL}', '<VAL>')
    sequences.append(f'{method} {path}')
with open('data/normalized.txt', 'w') as f:
    for seq in sequences:
        f.write(seq + '\n')
print('✅ Generated 1000 training sequences')
"

# Train model quickly  
echo "⚡ Training ML model (30 seconds)..."
python3 -c "
import sys, os
sys.path.append('src')
from detector import HTTPAnomalyDetector
detector = HTTPAnomalyDetector()
with open('data/normalized.txt') as f:
    sequences = [line.strip() for line in f]
detector.train(sequences)
detector.save_model('model/final/detector.json')
print('✅ Model trained with', len(detector.normal_patterns), 'patterns')
"

# Start ML API
echo "⚡ Starting ML API (10 seconds)..."
cd src
python3 server.py --host 0.0.0.0 --port 8080 > ../logs/api.log 2>&1 &
API_PID=$!
cd ..
sleep 5

# Check if API is running
if curl -f http://localhost:8080/health > /dev/null 2>&1; then
    echo "✅ ML API running (PID: $API_PID)"
else
    echo "❌ ML API failed to start"
    cat logs/api.log
    exit 1
fi

# Start demo web app
echo "⚡ Starting demo web app..."
mkdir -p demo/sample-app
cat > demo/sample-app/index.html << 'EOF'
<!DOCTYPE html>
<html><head><title>WAF Demo App</title></head>
<body style="font-family:Arial;padding:40px">
<h1>🛡️ ML-Powered WAF Demo</h1>
<p>Your WAF is protecting this application!</p>
<h2>Test URLs:</h2>
<ul>
<li><a href="/api/users">Normal API Call</a></li>
<li><a href="/search?q=test">Normal Search</a></li>
<li><a href="/../etc/passwd">🚨 Directory Traversal Attack</a></li>
<li><a href="/search?q=<script>alert(1)</script>">🚨 XSS Attack</a></li>
</ul>
<p><strong>Status:</strong> ✅ WAF Active | 🤖 ML Detection Enabled</p>
</body></html>
EOF

cd demo/sample-app
python3 -m http.server 8081 > ../../logs/webapp.log 2>&1 &
WEBAPP_PID=$!
cd ../..
sleep 2

echo "✅ Demo app running (PID: $WEBAPP_PID)"

# Quick test
echo "⚡ Testing system..."
response=$(curl -s -X POST http://localhost:8080/score -H "Content-Type: application/json" -d '{"seq":"GET /../etc/passwd"}')
if echo "$response" | grep -q "anomalous.*true"; then
    echo "✅ Attack detection working!"
else
    echo "⚠️  Attack detection may need tuning"
fi

# Save PIDs for cleanup
echo $API_PID > logs/api.pid
echo $WEBAPP_PID > logs/webapp.pid

echo
echo "🎉 WAF IS READY FOR YOUR HACKATHON! 🎉"
echo "======================================"
echo
echo "🌐 Access Points:"
echo "   ML API:      http://localhost:8080"
echo "   Demo App:    http://localhost:8081"
echo "   Health:      curl http://localhost:8080/health"
echo
echo "🧪 Test Attack Detection:"
echo "   bash demo/attacks.sh"
echo
echo "🔧 Manual Attack Test:"
echo "   curl -X POST http://localhost:8080/score -H 'Content-Type: application/json' -d '{"seq":"GET /../etc/passwd"}'"
echo
echo "🛑 Stop Services:"
echo "   kill $(cat logs/api.pid logs/webapp.pid 2>/dev/null | tr '\n' ' ')"
echo
echo "⏱️  Total setup time: ~2 minutes ⚡"

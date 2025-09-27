# Create comprehensive setup script
setup_script = '''#!/bin/bash
# Complete WAF Setup Script - One-command deployment
set -e

echo "🛡️  ML-powered WAF Setup Script"
echo "================================"
echo "This script will set up a complete ML-powered WAF system with:"
echo "- Synthetic log generation and model training"
echo "- FastAPI ML inference sidecar"
echo "- OpenResty/Nginx WAF integration"
echo "- Docker containerization"
echo "- Demo attack scenarios"
echo

# Configuration
PROJECT_NAME="webapp-ml-waf"
PYTHON_VERSION="3.8"

# Colors for output
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
BLUE='\\033[0;34m'
NC='\\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check if running in project directory
check_project_directory() {
    if [ ! -f "README.md" ] || [ ! -d "src" ]; then
        log_error "Please run this script from the project root directory"
        exit 1
    fi
    log_success "Project directory confirmed"
}

# Check system requirements
check_requirements() {
    log_info "Checking system requirements..."
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is required but not installed"
        exit 1
    fi
    
    python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    log_success "Python $python_version found"
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_warning "Docker not found - will install Python environment instead"
        USE_DOCKER=false
    else
        log_success "Docker found"
        USE_DOCKER=true
    fi
    
    # Check curl
    if ! command -v curl &> /dev/null; then
        log_error "curl is required but not installed"
        exit 1
    fi
    log_success "curl found"
}

# Setup Python environment
setup_python_env() {
    log_info "Setting up Python virtual environment..."
    
    if [ ! -d "venv" ]; then
        python3 -m venv venv
        log_success "Virtual environment created"
    else
        log_info "Virtual environment already exists"
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install requirements
    if [ -f "requirements.txt" ]; then
        log_info "Installing Python dependencies..."
        pip install -r requirements.txt
        log_success "Python dependencies installed"
    else
        log_warning "requirements.txt not found, installing minimal dependencies"
        pip install fastapi uvicorn numpy tokenizers requests
    fi
}

# Generate training data
generate_training_data() {
    log_info "Generating synthetic training data..."
    
    # Ensure directories exist
    mkdir -p data model/final logs
    
    # Generate logs
    python scripts/gen_logs.py --entries 2000 --output data/benign_logs.log --normalized data/normalized.txt
    
    log_success "Training data generated"
}

# Train ML model
train_model() {
    log_info "Training ML anomaly detection model..."
    
    # Train the detector
    python src/detector.py --train data/normalized.txt --model model/final/detector.json --validate
    
    log_success "ML model trained and saved"
}

# Setup configuration files
setup_config() {
    log_info "Setting up configuration files..."
    
    # Create settings.json
    cat > config/settings.json << EOF
{
  "anomaly_threshold": 0.5,
  "model_path": "model/final/detector.json",
  "log_path": "logs/waf_detections.log",
  "api_host": "0.0.0.0",
  "api_port": 8080,
  "batch_size": 32,
  "timeout_ms": 2000,
  "enable_caching": true,
  "cache_ttl_seconds": 60
}
EOF
    
    # Create sample app content
    mkdir -p demo/sample-app
    cat > demo/sample-app/index.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Sample Web Application</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        .header { background: #f4f4f4; padding: 20px; border-radius: 5px; }
        .api-demo { background: #e8f5e8; padding: 15px; margin: 20px 0; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ ML-Powered WAF Demo Application</h1>
            <p>This is a sample web application protected by an ML-based Web Application Firewall.</p>
        </div>
        
        <h2>Features Protected:</h2>
        <ul>
            <li>SQL Injection attacks</li>
            <li>Cross-Site Scripting (XSS)</li>
            <li>Directory traversal attempts</li>
            <li>Admin panel access attempts</li>
            <li>Command injection</li>
            <li>Buffer overflow attempts</li>
        </ul>
        
        <div class="api-demo">
            <h3>API Endpoints (for testing):</h3>
            <ul>
                <li><code>GET /api/users</code> - List users</li>
                <li><code>GET /api/user/{id}</code> - Get user details</li>
                <li><code>POST /api/login</code> - Login endpoint</li>
                <li><code>GET /search?q={query}</code> - Search functionality</li>
            </ul>
        </div>
        
        <h2>WAF Status:</h2>
        <p>✅ ML Anomaly Detection Active</p>
        <p>🔍 Real-time request analysis enabled</p>
        <p>📊 Attack detection logging enabled</p>
        
        <small>Protected by ML-WAF v1.0</small>
    </div>
</body>
</html>
EOF
    
    log_success "Configuration files created"
}

# Start services based on deployment type
start_services_docker() {
    log_info "Starting services with Docker Compose..."
    
    # Build and start services
    docker-compose up --build -d
    
    # Wait for services to be healthy
    log_info "Waiting for services to start..."
    sleep 10
    
    # Check service health
    if docker-compose ps | grep -q "unhealthy\\|Exit"; then
        log_error "Some services failed to start properly"
        docker-compose logs
        exit 1
    fi
    
    log_success "All services started successfully"
}

start_services_native() {
    log_info "Starting services natively..."
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Start ML sidecar in background
    log_info "Starting ML sidecar API..."
    python src/server.py --host 0.0.0.0 --port 8080 > logs/sidecar.log 2>&1 &
    SIDECAR_PID=$!
    echo $SIDECAR_PID > logs/sidecar.pid
    
    # Wait for sidecar to start
    sleep 5
    
    # Check if sidecar is running
    if ! curl -f http://localhost:8080/health > /dev/null 2>&1; then
        log_error "ML sidecar failed to start"
        cat logs/sidecar.log
        exit 1
    fi
    
    log_success "ML sidecar started (PID: $SIDECAR_PID)"
    
    # Start sample app
    log_info "Starting sample web application..."
    cd demo/sample-app
    python -m http.server 8081 > ../../logs/webapp.log 2>&1 &
    WEBAPP_PID=$!
    cd ../..
    echo $WEBAPP_PID > logs/webapp.pid
    
    log_success "Sample web application started (PID: $WEBAPP_PID)"
    log_warning "Note: OpenResty/Nginx integration requires Docker or manual OpenResty installation"
}

# Run basic tests
run_tests() {
    log_info "Running basic functionality tests..."
    
    # Test ML API
    if curl -f http://localhost:8080/health > /dev/null 2>&1; then
        log_success "ML API health check passed"
    else
        log_error "ML API health check failed"
        return 1
    fi
    
    # Test anomaly detection
    response=$(curl -s -X POST http://localhost:8080/score \\
        -H "Content-Type: application/json" \\
        -d '{"seq": "GET /test"}')
    
    if echo "$response" | grep -q "score"; then
        log_success "Anomaly detection API working"
    else
        log_error "Anomaly detection API failed"
        return 1
    fi
    
    # Test sample app (if running natively)
    if [ "$USE_DOCKER" = false ] && curl -f http://localhost:8081 > /dev/null 2>&1; then
        log_success "Sample web application accessible"
    fi
    
    log_success "All tests passed"
}

# Display final information
show_final_info() {
    echo
    echo "🎉 WAF Setup Complete!"
    echo "======================="
    echo
    
    if [ "$USE_DOCKER" = true ]; then
        echo "🐳 Docker Services:"
        echo "   ML API:          http://localhost:8080"
        echo "   WAF Gateway:     http://localhost (with attack detection)"
        echo "   Sample App:      http://localhost:8081 (direct access)"
        echo "   Grafana:         http://localhost:3000 (admin/admin) [optional]"
        echo
        echo "📋 Useful Commands:"
        echo "   View logs:       docker-compose logs -f"
        echo "   Stop services:   docker-compose down"
        echo "   Restart:         docker-compose restart"
    else
        echo "🐍 Native Python Services:"
        echo "   ML API:          http://localhost:8080"
        echo "   Sample App:      http://localhost:8081"
        echo
        echo "📋 Service Management:"
        echo "   Stop sidecar:    kill \\$(cat logs/sidecar.pid)"
        echo "   Stop webapp:     kill \\$(cat logs/webapp.pid)"
        echo "   View logs:       tail -f logs/*.log"
    fi
    
    echo
    echo "🧪 Testing:"
    echo "   Run attacks:     bash demo/attacks.sh"
    echo "   Generate traffic: python scripts/generate_traffic.py --requests 100"
    echo "   View detections: tail -f logs/waf_detections.log"
    echo
    echo "📊 Monitoring:"
    echo "   API stats:       curl http://localhost:8080/stats"
    echo "   Health check:    curl http://localhost:8080/health"
    echo
    echo "🔧 Advanced:"
    echo "   Retrain model:   python src/incremental_tune.py --new_logs data/new_benign.txt"
    echo "   Update threshold: curl -X POST http://localhost:8080/update_threshold -d '0.4'"
    echo
    
    log_success "WAF is ready for your hackathon demo! 🚀"
}

# Cleanup function
cleanup() {
    if [ "$USE_DOCKER" = false ]; then
        if [ -f "logs/sidecar.pid" ]; then
            kill $(cat logs/sidecar.pid) 2>/dev/null || true
        fi
        if [ -f "logs/webapp.pid" ]; then
            kill $(cat logs/webapp.pid) 2>/dev/null || true
        fi
    fi
}

# Trap cleanup on exit
trap cleanup EXIT

# Main execution flow
main() {
    check_project_directory
    check_requirements
    
    if [ "$USE_DOCKER" = true ]; then
        setup_config
        start_services_docker
    else
        setup_python_env
        generate_training_data
        train_model
        setup_config
        start_services_native
    fi
    
    run_tests
    show_final_info
}

# Handle command line arguments
case "${1:-setup}" in
    setup)
        main
        ;;
    clean)
        log_info "Cleaning up WAF environment..."
        docker-compose down -v 2>/dev/null || true
        rm -rf venv logs/*.log logs/*.pid data/benign_logs.log data/normalized.txt model/final/detector.json
        log_success "Environment cleaned"
        ;;
    restart)
        log_info "Restarting WAF services..."
        if [ "$USE_DOCKER" = true ]; then
            docker-compose restart
        else
            cleanup
            start_services_native
        fi
        log_success "Services restarted"
        ;;
    *)
        echo "Usage: $0 {setup|clean|restart}"
        echo "  setup   - Full WAF setup and deployment"
        echo "  clean   - Clean environment and remove generated files"
        echo "  restart - Restart all services"
        exit 1
        ;;
esac
'''

with open("webapp-ml-waf/setup.sh", "w") as f:
    f.write(setup_script)

# Make it executable
os.chmod("webapp-ml-waf/setup.sh", stat.S_IRWXU | stat.S_IRGRP | stat.S_IROTH)

# Create quick start script
quick_start = '''#!/bin/bash
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
        f.write(seq + '\\n')
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
echo "   curl -X POST http://localhost:8080/score -H 'Content-Type: application/json' -d '{\"seq\":\"GET /../etc/passwd\"}'"
echo
echo "🛑 Stop Services:"
echo "   kill $(cat logs/api.pid logs/webapp.pid 2>/dev/null | tr '\\n' ' ')"
echo
echo "⏱️  Total setup time: ~2 minutes ⚡"
'''

with open("webapp-ml-waf/quick_start.sh", "w") as f:
    f.write(quick_start)

os.chmod("webapp-ml-waf/quick_start.sh", stat.S_IRWXU | stat.S_IRGRP | stat.S_IROTH)

# Create configuration file
config_json = '''{
  "anomaly_threshold": 0.5,
  "model_path": "model/final/detector.json",
  "tokenizer_path": "model/tokenizer.json",
  "log_path": "logs/waf_detections.log",
  "api": {
    "host": "0.0.0.0",
    "port": 8080,
    "workers": 1,
    "timeout": 30
  },
  "detection": {
    "enable_token_analysis": true,
    "enable_rule_analysis": true,
    "token_weight": 0.6,
    "rule_weight": 0.4,
    "max_sequence_length": 200
  },
  "caching": {
    "enable": true,
    "ttl_seconds": 60,
    "max_size": 1000
  },
  "logging": {
    "level": "INFO",
    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  }
}'''

with open("webapp-ml-waf/config/settings.json", "w") as f:
    f.write(config_json)

print("✅ Created setup scripts and configuration")
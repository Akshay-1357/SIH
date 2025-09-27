# Makefile for ML-powered WAF

.PHONY: help install start stop test clean demo docker-build docker-start

help:	## Show this help message
	@echo "ML-powered WAF - Available Commands:"
	@echo "====================================="
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# Quick setup commands
quick-start: ## 🚀 Quick start for hackathon demo (2 minutes)
	@./quick_start.sh

install:	## 📦 Full installation and setup
	@./setup.sh

# Service management
start:		## ▶️  Start WAF services
	@echo "Starting WAF services..."
	@source venv/bin/activate && python src/server.py --host 0.0.0.0 --port 8080 &
	@echo "✅ Services started"

stop:		## ⏹️  Stop WAF services  
	@echo "Stopping WAF services..."
	@pkill -f "python src/server.py" || true
	@pkill -f "python -m http.server 8081" || true
	@echo "✅ Services stopped"

restart:	## 🔄 Restart WAF services
	@make stop
	@sleep 2
	@make start

# Testing and demo
test:		## 🧪 Run test suite
	@echo "Running WAF test suite..."
	@python tests/test_waf.py

demo:		## 🎯 Run attack demonstration
	@echo "Running attack demonstration..."
	@bash demo/attacks.sh

load-test:	## 📊 Run load testing
	@echo "Running load test with 1000 requests..."
	@python scripts/generate_traffic.py --requests 1000 --concurrent 10

# Data and model management  
generate-data: ## 📊 Generate training data
	@echo "Generating synthetic training data..."
	@python scripts/gen_logs.py --entries 2000

train-model: ## 🤖 Train ML model
	@echo "Training anomaly detection model..."
	@python src/detector.py --train data/normalized.txt --model model/final/detector.json --validate

retrain:	## 🔄 Retrain model with incremental data
	@echo "Performing incremental training..."
	@python src/incremental_tune.py --new_logs data/new_benign.txt --epochs 1

# Docker operations
docker-build: ## 🐳 Build Docker images
	@echo "Building Docker images..."
	@docker-compose build

docker-start: ## 🐳 Start with Docker Compose
	@echo "Starting WAF with Docker..."
	@docker-compose up -d

docker-stop: ## 🐳 Stop Docker services
	@echo "Stopping Docker services..."
	@docker-compose down

docker-logs: ## 📋 View Docker logs
	@docker-compose logs -f

# Maintenance
clean:		## 🧹 Clean generated files and logs
	@echo "Cleaning WAF environment..."
	@rm -rf logs/*.log logs/*.pid data/benign_logs.log data/normalized.txt
	@rm -rf model/final/detector.json venv __pycache__ src/__pycache__
	@echo "✅ Environment cleaned"

clean-all:	## 🧹 Full cleanup including Docker
	@make clean
	@docker-compose down -v --remove-orphans
	@docker system prune -f

# Development
dev-setup:	## 🔧 Setup development environment
	@python3 -m venv venv
	@source venv/bin/activate && pip install -r requirements-dev.txt
	@echo "✅ Development environment ready"

format:		## 🎨 Format code with black
	@source venv/bin/activate && black src/ tests/ scripts/

lint:		## 🔍 Run code linting
	@source venv/bin/activate && flake8 src/ tests/ scripts/

# Monitoring
status:		## 📊 Check WAF status
	@echo "WAF System Status:"
	@echo "=================="
	@curl -s http://localhost:8080/health | python3 -m json.tool || echo "❌ ML API not responding"
	@echo
	@curl -s http://localhost:8080/stats | python3 -m json.tool || echo "❌ Stats not available"

logs:		## 📋 View live logs
	@echo "Viewing WAF logs (Ctrl+C to exit)..."
	@tail -f logs/*.log

detections:	## 🚨 View attack detections
	@echo "Recent attack detections:"
	@tail -20 logs/waf_detections.log 2>/dev/null || echo "No detections logged yet"

# Information
info:		## ℹ️  Show system information
	@echo "ML-powered WAF System Information"
	@echo "================================="
	@echo "Python version: $$(python3 --version)"
	@echo "Docker version: $$(docker --version 2>/dev/null || echo 'Not installed')"
	@echo "Project directory: $$(pwd)"
	@echo "Virtual environment: $$([ -d venv ] && echo 'Present' || echo 'Missing')"
	@echo "Model trained: $$([ -f model/final/detector.json ] && echo 'Yes' || echo 'No')"
	@echo "Services running: $$(pgrep -f 'python src/server.py' > /dev/null && echo 'Yes' || echo 'No')"

# Hackathon specific
hackathon-demo: ## 🏆 Full hackathon demonstration
	@echo "🏆 Starting Full Hackathon Demo"
	@echo "==============================="
	@make quick-start
	@sleep 5
	@echo "\n🧪 Running attack scenarios..."
	@make demo
	@echo "\n📊 Showing system stats..."
	@make status
	@echo "\n🎉 Demo complete! Your WAF is ready to impress the judges!"

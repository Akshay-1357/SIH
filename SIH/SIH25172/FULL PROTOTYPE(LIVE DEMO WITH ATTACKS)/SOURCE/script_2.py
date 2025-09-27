# Create requirements.txt
requirements = '''# Core ML and API dependencies
fastapi==0.104.1
uvicorn[standard]==0.24.0
pydantic==2.5.0
tokenizers==0.15.0
numpy==1.24.3
requests==2.31.0

# Optional ML libraries (for advanced models)
transformers==4.35.0
torch==2.1.0
datasets==2.14.5

# Development and testing
pytest==7.4.3
black==23.9.1
flake8==6.1.0
mypy==1.6.1
pre-commit==3.5.0

# Monitoring and metrics
prometheus-client==0.19.0
psutil==5.9.6

# Logging and utilities
structlog==23.2.0
apache-log-parser==1.7.0
'''

with open("webapp-ml-waf/requirements.txt", "w") as f:
    f.write(requirements)

# Create requirements-dev.txt
requirements_dev = '''# Include production requirements
-r requirements.txt

# Additional development tools
jupyter==1.0.0
ipykernel==6.26.0
matplotlib==3.8.0
seaborn==0.13.0
pandas==2.1.2
scikit-learn==1.3.0

# Code quality
isort==5.12.0
autopep8==2.0.4
bandit==1.7.5
coverage==7.3.2

# Documentation
sphinx==7.2.6
sphinx-rtd-theme==1.3.0
mkdocs==1.5.3
'''

with open("webapp-ml-waf/requirements-dev.txt", "w") as f:
    f.write(requirements_dev)

print("✅ Created requirements files")
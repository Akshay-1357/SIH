# Create the FastAPI server for ML inference (Day 3)
server_script = '''#!/usr/bin/env python3
"""
FastAPI ML Sidecar Server for HTTP Anomaly Detection.
Provides async inference API for real-time WAF integration.
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
import uvicorn
import json
import os
import time
import logging
from typing import Dict, List, Optional
from contextlib import asynccontextmanager

from detector import HTTPAnomalyDetector

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global detector instance
detector = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan events"""
    # Startup
    global detector
    logger.info("Starting ML Sidecar Server...")
    
    # Initialize detector
    detector = HTTPAnomalyDetector()
    
    # Load existing model if available
    model_path = "model/final/detector.json"
    if os.path.exists(model_path):
        try:
            detector.load_model(model_path)
            logger.info("✅ Existing model loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load existing model: {e}")
            # Train on default data if available
            await _train_default_model()
    else:
        logger.warning("No existing model found, training default model...")
        await _train_default_model()
    
    yield
    
    # Shutdown
    logger.info("Shutting down ML Sidecar Server...")

async def _train_default_model():
    """Train model with default/generated data if no model exists"""
    global detector
    
    # Check for normalized training data
    training_file = "data/normalized.txt"
    
    if not os.path.exists(training_file):
        logger.info("No training data found, generating synthetic data...")
        # Generate some basic patterns for demo
        default_patterns = [
            "GET /", "POST /login", "GET /api/item/<ID>", "POST /api/user/<ID>",
            "GET /dashboard", "POST /api/items", "GET /search?q=<VAL>", 
            "GET /profile/<ID>", "POST /logout", "GET /health",
            "GET /static/css/<TOKEN>", "GET /static/js/<TOKEN>",
            "POST /api/auth", "GET /api/stats", "PUT /api/item/<ID>"
        ]
        
        # Create training data
        os.makedirs("data", exist_ok=True)
        with open(training_file, 'w') as f:
            # Generate multiple instances of each pattern
            for pattern in default_patterns:
                for _ in range(50):  # 50 instances each
                    f.write(pattern + '\\n')
        
        logger.info(f"Generated {len(default_patterns) * 50} training sequences")
    
    # Train the model
    try:
        with open(training_file, 'r') as f:
            sequences = [line.strip() for line in f.readlines() if line.strip()]
        
        logger.info(f"Training detector on {len(sequences)} sequences...")
        detector.train(sequences)
        
        # Save the model
        os.makedirs("model/final", exist_ok=True)
        detector.save_model("model/final/detector.json")
        
        logger.info("✅ Default model trained and saved successfully")
        
    except Exception as e:
        logger.error(f"Failed to train default model: {e}")

# Initialize FastAPI app
app = FastAPI(
    title="HTTP Anomaly Detection API",
    description="ML-powered WAF sidecar for real-time HTTP anomaly detection",
    version="1.0.0",
    lifespan=lifespan
)

# Request/Response models
class AnomalyRequest(BaseModel):
    seq: str = Field(..., description="HTTP sequence to analyze (e.g., 'GET /api/item/<ID>')")

class AnomalyResponse(BaseModel):
    sequence: str
    score: float = Field(..., description="Anomaly score (0.0-1.0, higher = more anomalous)")
    anomalous: bool = Field(..., description="True if sequence is classified as anomalous")
    confidence: str = Field(..., description="Confidence level: very_low, low, medium, high, very_high")
    processing_time_ms: float = Field(..., description="Processing time in milliseconds")

class BatchRequest(BaseModel):
    sequences: List[str] = Field(..., description="List of HTTP sequences to analyze")

class BatchResponse(BaseModel):
    predictions: List[AnomalyResponse]
    total_processed: int
    total_anomalies: int
    processing_time_ms: float

class StatsResponse(BaseModel):
    model_info: Dict
    performance_stats: Dict
    uptime_seconds: float

class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    uptime_seconds: float
    version: str

# Global stats for uptime tracking
start_time = time.time()

@app.get("/", response_model=Dict)
async def root():
    """API root endpoint with basic information"""
    return {
        "service": "HTTP Anomaly Detection API",
        "version": "1.0.0",
        "status": "running",
        "model_loaded": detector is not None and detector.is_trained,
        "endpoints": {
            "score": "POST /score - Single sequence anomaly detection",
            "batch": "POST /batch_predict - Batch anomaly detection",
            "health": "GET /health - Health check",
            "stats": "GET /stats - Model and performance statistics",
            "retrain": "POST /retrain - Trigger model retraining"
        }
    }

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    if detector is None or not detector.is_trained:
        raise HTTPException(status_code=503, detail="Model not loaded or trained")
    
    uptime = time.time() - start_time
    
    return HealthResponse(
        status="healthy",
        model_loaded=True,
        uptime_seconds=round(uptime, 2),
        version="1.0.0"
    )

@app.post("/score", response_model=AnomalyResponse)
async def predict_anomaly(request: AnomalyRequest):
    """
    Predict anomaly score for a single HTTP sequence.
    
    This is the main endpoint used by OpenResty for real-time detection.
    """
    if detector is None or not detector.is_trained:
        raise HTTPException(status_code=503, detail="Model not loaded or trained")
    
    start_time_ms = time.time() * 1000
    
    try:
        # Get detailed prediction
        details = detector.get_prediction_details(request.seq)
        
        processing_time = (time.time() * 1000) - start_time_ms
        
        return AnomalyResponse(
            sequence=details['sequence'],
            score=details['anomaly_score'],
            anomalous=details['is_anomaly'],
            confidence=details['confidence'],
            processing_time_ms=round(processing_time, 2)
        )
        
    except Exception as e:
        logger.error(f"Prediction error for sequence '{request.seq}': {e}")
        raise HTTPException(status_code=500, detail=f"Prediction failed: {str(e)}")

@app.post("/batch_predict", response_model=BatchResponse)
async def batch_predict(request: BatchRequest):
    """Batch prediction for multiple sequences"""
    if detector is None or not detector.is_trained:
        raise HTTPException(status_code=503, detail="Model not loaded or trained")
    
    start_time_ms = time.time() * 1000
    
    try:
        predictions = []
        anomaly_count = 0
        
        for seq in request.sequences:
            seq_start = time.time() * 1000
            details = detector.get_prediction_details(seq)
            seq_time = (time.time() * 1000) - seq_start
            
            response = AnomalyResponse(
                sequence=details['sequence'],
                score=details['anomaly_score'],
                anomalous=details['is_anomaly'],
                confidence=details['confidence'],
                processing_time_ms=round(seq_time, 2)
            )
            
            predictions.append(response)
            
            if details['is_anomaly']:
                anomaly_count += 1
        
        total_time = (time.time() * 1000) - start_time_ms
        
        return BatchResponse(
            predictions=predictions,
            total_processed=len(request.sequences),
            total_anomalies=anomaly_count,
            processing_time_ms=round(total_time, 2)
        )
        
    except Exception as e:
        logger.error(f"Batch prediction error: {e}")
        raise HTTPException(status_code=500, detail=f"Batch prediction failed: {str(e)}")

@app.get("/stats", response_model=StatsResponse)
async def get_statistics():
    """Get model and performance statistics"""
    if detector is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    
    uptime = time.time() - start_time
    
    try:
        stats = detector.get_statistics()
        
        return StatsResponse(
            model_info=stats['model_info'],
            performance_stats={
                k: v for k, v in stats.items() if k != 'model_info'
            },
            uptime_seconds=round(uptime, 2)
        )
        
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        raise HTTPException(status_code=500, detail=f"Statistics error: {str(e)}")

@app.post("/retrain")
async def retrain_model(background_tasks: BackgroundTasks):
    """Trigger model retraining with latest data"""
    if detector is None:
        raise HTTPException(status_code=503, detail="Detector not initialized")
    
    def retrain_task():
        try:
            training_file = "data/normalized.txt"
            if os.path.exists(training_file):
                with open(training_file, 'r') as f:
                    sequences = [line.strip() for line in f.readlines() if line.strip()]
                
                logger.info(f"Retraining with {len(sequences)} sequences...")
                detector.train(sequences)
                detector.save_model("model/final/detector.json")
                logger.info("✅ Model retrained successfully")
            else:
                logger.warning("No training data found for retraining")
                
        except Exception as e:
            logger.error(f"Retraining failed: {e}")
    
    background_tasks.add_task(retrain_task)
    
    return {"message": "Retraining started in background"}

@app.post("/update_threshold")
async def update_threshold(threshold: float):
    """Update anomaly detection threshold"""
    if detector is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    
    try:
        detector.update_threshold(threshold)
        return {"message": f"Threshold updated to {threshold}"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

# Error handlers
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler"""
    logger.error(f"Unhandled exception: {exc}")
    return HTTPException(status_code=500, detail="Internal server error")

def main():
    """Main function to run the server"""
    import argparse
    
    parser = argparse.ArgumentParser(description="HTTP Anomaly Detection ML Sidecar")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8080, help="Port to bind to") 
    parser.add_argument("--workers", type=int, default=1, help="Number of worker processes")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload for development")
    parser.add_argument("--log-level", default="info", help="Log level")
    
    args = parser.parse_args()
    
    logger.info(f"Starting server on {args.host}:{args.port}")
    
    uvicorn.run(
        "server:app",
        host=args.host,
        port=args.port,
        workers=args.workers if not args.reload else 1,
        reload=args.reload,
        log_level=args.log_level,
        access_log=True
    )

if __name__ == "__main__":
    main()
'''

with open("webapp-ml-waf/src/server.py", "w") as f:
    f.write(server_script)

print("✅ Created FastAPI server")
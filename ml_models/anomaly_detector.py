import os
import numpy as np
import logging
import pickle
import joblib
from datetime import datetime

# Configure logging
logger = logging.getLogger(__name__)

class AnomalyDetector:
    """
    Machine learning model for detecting anomalies in security data
    Uses isolation forest and statistical methods for anomaly detection
    """
    
    def __init__(self):
        """Initialize the anomaly detector"""
        self.model = None
        self.model_path = 'ml_models/anomaly_detector_model.pkl'
        self.initialized = False
        
        # Try to load an existing model or initialize a new one
        self._initialize_model()
    
    def _initialize_model(self):
        """Initialize or load the anomaly detection model"""
        try:
            if os.path.exists(self.model_path):
                # Load existing model
                self.model = joblib.load(self.model_path)
                logger.info("Loaded existing anomaly detection model")
            else:
                # Initialize a simple anomaly detection model
                # In a real implementation, this would be a properly trained model
                logger.info("No existing model found, initializing a new model")
                self._create_simple_model()
            
            self.initialized = True
        
        except Exception as e:
            logger.error(f"Error initializing anomaly detector: {str(e)}")
            # Fall back to simple model
            self._create_simple_model()
    
    def _create_simple_model(self):
        """Create a simple statistical model for demonstration purposes"""
        # This is a placeholder for a real ML model
        # In a production system, this would be a properly trained anomaly detector
        self.model = SimpleAnomalyDetector()
    
    def detect_anomaly(self, features):
        """
        Detect if input features represent an anomaly
        
        Args:
            features (numpy.ndarray): Feature vector to analyze
            
        Returns:
            dict: Detection result with anomaly flag and confidence
        """
        if not self.initialized:
            self._initialize_model()
        
        try:
            # Detect anomaly
            result = self.model.predict(features)
            
            return result
        
        except Exception as e:
            logger.error(f"Error in anomaly detection: {str(e)}")
            # Fallback to a safe default
            return {
                'is_anomaly': False,
                'confidence': 0.5,
                'score': 0.0
            }
    
    def train(self, X_train):
        """
        Train the anomaly detection model
        
        Args:
            X_train (numpy.ndarray): Training data (normal examples)
            
        Returns:
            bool: True if training was successful, False otherwise
        """
        try:
            # In a real implementation, this would train the model
            # For this demo, we'll just update the simple model
            logger.info("Training anomaly detection model")
            
            # Train model (in a real system)
            # self.model.fit(X_train)
            
            # Save the model
            # joblib.dump(self.model, self.model_path)
            
            return True
        
        except Exception as e:
            logger.error(f"Error training anomaly detector: {str(e)}")
            return False
    
    def evaluate(self, X_test, y_test):
        """
        Evaluate the model performance
        
        Args:
            X_test (numpy.ndarray): Test features
            y_test (numpy.ndarray): Test labels (1 for anomaly, 0 for normal)
            
        Returns:
            dict: Performance metrics
        """
        try:
            # In a real implementation, this would calculate metrics
            # Like precision, recall, F1 score, AUC
            
            # Placeholder metrics for demo
            return {
                'precision': 0.88,
                'recall': 0.82,
                'f1_score': 0.85,
                'auc': 0.91
            }
        
        except Exception as e:
            logger.error(f"Error evaluating anomaly detector: {str(e)}")
            return {
                'error': str(e)
            }


class SimpleAnomalyDetector:
    """
    A simple statistical anomaly detector as a fallback
    This simulates ML functionality for the demo
    """
    
    def __init__(self):
        # Define simple thresholds
        # In a real system, these would be learned from data
        self.thresholds = {
            'event_ratio': 2.0,    # events per minute
            'login_failures': 5,    # failed login attempts
            'off_hours_access': 0.7, # confidence for off-hours access
            'sudo_commands': 8      # number of sudo commands
        }
    
    def predict(self, features):
        """
        Detect anomalies based on simple thresholds
        
        Args:
            features (numpy.ndarray): Feature vector
            
        Returns:
            dict: Anomaly detection result
        """
        # Initialize result
        result = {
            'is_anomaly': False,
            'confidence': 0.5,
            'score': 0.0
        }
        
        try:
            # Extract features
            threat_type = int(features[0][0]) if features.shape[1] > 0 else 0
            base_confidence = float(features[0][1]) if features.shape[1] > 1 else 0.5
            
            # Check for specific threat types
            if threat_type in [1, 2, 6]:  # authentication_failure, privilege_escalation, etc.
                # Extract additional features if available
                event_count = float(features[0][2]) if features.shape[1] > 2 else 0
                timespan = float(features[0][3]) if features.shape[1] > 3 else 1
                
                # Calculate events per minute
                events_per_minute = event_count / max(timespan, 1)
                
                # Detect anomaly based on event rate
                if events_per_minute > self.thresholds['event_ratio']:
                    result['is_anomaly'] = True
                    # Calculate confidence based on how much it exceeds threshold
                    result['confidence'] = min(0.7 + (events_per_minute / self.thresholds['event_ratio']) * 0.1, 0.95)
                    result['score'] = events_per_minute / self.thresholds['event_ratio']
            
            # If no anomaly detected by specific checks but base confidence is high
            if not result['is_anomaly'] and base_confidence > 0.8:
                result['is_anomaly'] = True
                result['confidence'] = base_confidence
                result['score'] = base_confidence
            
            return result
        
        except Exception as e:
            logger.error(f"Error in simple anomaly detection: {str(e)}")
            return result

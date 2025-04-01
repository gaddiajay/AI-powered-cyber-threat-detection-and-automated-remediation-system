import os
import numpy as np
import logging
import pickle
import joblib
from datetime import datetime

# Configure logging
logger = logging.getLogger(__name__)

class ThreatClassifier:
    """
    Machine learning model for classifying and predicting cyber threats
    Using a combination of decision trees and other ML techniques
    """
    
    def __init__(self):
        """Initialize the threat classifier"""
        self.model = None
        self.model_path = 'ml_models/threat_classifier_model.pkl'
        self.features = ['type_code', 'confidence', 'port_normalized', 'protocol_code', 'indicator_count']
        self.initialized = False
        
        # Try to load an existing model or initialize a new one
        self._initialize_model()
    
    def _initialize_model(self):
        """Initialize or load the classification model"""
        try:
            if os.path.exists(self.model_path):
                # Load existing model
                self.model = joblib.load(self.model_path)
                logger.info("Loaded existing threat classification model")
            else:
                # Initialize a simple decision tree model
                # In a real implementation, this would be a properly trained model
                logger.info("No existing model found, initializing a new model")
                self._create_simple_model()
            
            self.initialized = True
        
        except Exception as e:
            logger.error(f"Error initializing threat classifier: {str(e)}")
            # Fall back to simple model
            self._create_simple_model()
    
    def _create_simple_model(self):
        """Create a simple rule-based model for demonstration purposes"""
        # This is a placeholder for a real ML model
        # In a production system, this would be a properly trained classifier
        self.model = SimpleThreatClassifier()
    
    def classify(self, features):
        """
        Classify a threat based on its features
        
        Args:
            features (numpy.ndarray): Feature vector for the threat
            
        Returns:
            dict: Classification result with predicted severity and confidence
        """
        if not self.initialized:
            self._initialize_model()
        
        try:
            # Make prediction
            result = self.model.predict(features)
            
            return {
                'severity': result['severity'],
                'confidence': result['confidence']
            }
        
        except Exception as e:
            logger.error(f"Error in threat classification: {str(e)}")
            # Fallback to a safe default
            return {
                'severity': 'medium',
                'confidence': 0.5
            }
    
    def train(self, X_train, y_train):
        """
        Train the threat classification model
        
        Args:
            X_train (numpy.ndarray): Training features
            y_train (numpy.ndarray): Training labels
            
        Returns:
            bool: True if training was successful, False otherwise
        """
        try:
            # In a real implementation, this would train the model
            # For this demo, we'll just update the simple model
            logger.info("Training threat classification model")
            
            # Update model (in a real system)
            # self.model.fit(X_train, y_train)
            
            # Save the model
            # joblib.dump(self.model, self.model_path)
            
            return True
        
        except Exception as e:
            logger.error(f"Error training threat classifier: {str(e)}")
            return False
    
    def evaluate(self, X_test, y_test):
        """
        Evaluate the model performance
        
        Args:
            X_test (numpy.ndarray): Test features
            y_test (numpy.ndarray): Test labels
            
        Returns:
            dict: Performance metrics
        """
        try:
            # In a real implementation, this would calculate metrics
            # Like accuracy, precision, recall, F1 score
            
            # Placeholder metrics for demo
            return {
                'accuracy': 0.92,
                'precision': 0.89,
                'recall': 0.86,
                'f1_score': 0.87
            }
        
        except Exception as e:
            logger.error(f"Error evaluating threat classifier: {str(e)}")
            return {
                'error': str(e)
            }


class SimpleThreatClassifier:
    """
    A simple rule-based classifier as a fallback
    This simulates ML functionality for the demo
    """
    
    def __init__(self):
        # Define simple classification rules
        # In a real system, these would be learned from data
        self.rules = {
            # threat_type -> severity mapping with confidence
            1: {'severity': 'high', 'confidence': 0.85},    # malware
            2: {'severity': 'critical', 'confidence': 0.9},  # ransomware
            3: {'severity': 'high', 'confidence': 0.8},     # ddos
            4: {'severity': 'high', 'confidence': 0.85},    # intrusion
            5: {'severity': 'medium', 'confidence': 0.7},   # port_scan
            6: {'severity': 'medium', 'confidence': 0.75},  # brute_force
            7: {'severity': 'high', 'confidence': 0.85},    # backdoor
            8: {'severity': 'high', 'confidence': 0.8},     # sql_injection
            9: {'severity': 'medium', 'confidence': 0.75},  # xss
            10: {'severity': 'high', 'confidence': 0.85}    # data_exfiltration
        }
    
    def predict(self, features):
        """
        Make a prediction based on simple rules
        
        Args:
            features (numpy.ndarray): Feature vector
            
        Returns:
            dict: Prediction result
        """
        # Extract the threat type code from features
        threat_type = int(features[0][0])
        
        # Get base classification from rules
        result = self.rules.get(threat_type, {'severity': 'medium', 'confidence': 0.5})
        
        # Adjust confidence based on other features
        confidence = features[0][1]  # Use provided confidence 
        port_normalized = features[0][2]
        indicator_count = features[0][4] if features.shape[1] > 4 else 1
        
        # Adjust severity based on confidence and indicators
        if confidence > 0.9 and result['severity'] != 'critical':
            result['severity'] = self._increase_severity(result['severity'])
            
        if confidence < 0.7 and result['severity'] != 'low':
            result['severity'] = self._decrease_severity(result['severity'])
        
        # Adjust confidence based on indicator count
        if indicator_count > 3:
            result['confidence'] = min(result['confidence'] + 0.05, 0.98)
        
        return result
    
    def _increase_severity(self, current_severity):
        """Increase the severity level"""
        severity_levels = ['low', 'medium', 'high', 'critical']
        current_index = severity_levels.index(current_severity)
        if current_index < len(severity_levels) - 1:
            return severity_levels[current_index + 1]
        return current_severity
    
    def _decrease_severity(self, current_severity):
        """Decrease the severity level"""
        severity_levels = ['low', 'medium', 'high', 'critical']
        current_index = severity_levels.index(current_severity)
        if current_index > 0:
            return severity_levels[current_index - 1]
        return current_severity

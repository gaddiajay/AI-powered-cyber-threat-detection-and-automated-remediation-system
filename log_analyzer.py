import re
import json
import logging
import numpy as np
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from app import db
from models import Log, Threat, Alert
from ml_models.anomaly_detector import AnomalyDetector

# Configure logging
logger = logging.getLogger(__name__)

# Initialize anomaly detector
anomaly_detector = AnomalyDetector()

class LogAnalyzer:
    """Class for analyzing security logs and detecting potential threats"""
    
    def __init__(self):
        self.patterns = {
            'authentication_failure': r'failed login|authentication failure|invalid password|access denied',
            'privilege_escalation': r'sudo|privilege|root access|permission change|admin rights',
            'unusual_access': r'unauthorized access|unusual time|suspicious login|unexpected location',
            'malware_activity': r'malware|virus|trojan|ransomware|suspicious executable|malicious',
            'data_exfiltration': r'large file transfer|unusual download|data transfer|outbound traffic',
            'system_change': r'registry change|system file modified|configuration change|service started'
        }
        
        # Compile regex patterns for efficiency
        self.compiled_patterns = {key: re.compile(pattern, re.IGNORECASE) 
                                 for key, pattern in self.patterns.items()}
    
    def analyze_logs(self, time_range='24h', log_source=None, limit=1000):
        """
        Analyze logs to find potential security threats
        
        Args:
            time_range (str): Time range to analyze ('1h', '24h', '7d', '30d')
            log_source (str): Filter logs by source
            limit (int): Maximum number of logs to analyze
            
        Returns:
            list: List of potential threats detected
        """
        try:
            # Calculate start time based on time range
            start_time = self._calculate_start_time(time_range)
            
            # Query logs from the database
            query = Log.query.filter(Log.timestamp >= start_time)
            
            if log_source:
                query = query.filter(Log.source == log_source)
                
            logs = query.order_by(Log.timestamp.desc()).limit(limit).all()
            
            logger.info(f"Analyzing {len(logs)} logs from {start_time}")
            
            # Group logs by source for analysis
            logs_by_source = defaultdict(list)
            for log in logs:
                logs_by_source[log.source].append(log)
            
            # Detect threats in each group of logs
            threats = []
            for source, source_logs in logs_by_source.items():
                source_threats = self._detect_threats_in_logs(source, source_logs)
                threats.extend(source_threats)
            
            return threats
        
        except Exception as e:
            logger.error(f"Error analyzing logs: {str(e)}")
            return []
    
    def _calculate_start_time(self, time_range):
        """Calculate the start time based on the specified time range"""
        now = datetime.utcnow()
        
        if time_range == '1h':
            return now - timedelta(hours=1)
        elif time_range == '24h':
            return now - timedelta(days=1)
        elif time_range == '7d':
            return now - timedelta(days=7)
        elif time_range == '30d':
            return now - timedelta(days=30)
        else:
            # Default to 24 hours
            return now - timedelta(days=1)
    
    def _detect_threats_in_logs(self, source, logs):
        """Detect potential threats in a group of logs"""
        threats = []
        
        # Extract log messages for pattern matching
        log_messages = [log.message for log in logs]
        
        # Count occurrences of each threat type
        threat_counts = defaultdict(int)
        for message in log_messages:
            for threat_type, pattern in self.compiled_patterns.items():
                if pattern.search(message):
                    threat_counts[threat_type] += 1
        
        # Detect anomalies based on pattern matching
        for threat_type, count in threat_counts.items():
            if self._is_threat_anomaly(threat_type, count, len(logs)):
                # Create threat object
                threat = self._create_threat_from_logs(threat_type, source, logs, count)
                if threat:
                    threats.append(threat)
        
        # Perform time-based analysis for frequent events
        time_based_threats = self._analyze_time_patterns(logs)
        threats.extend(time_based_threats)
        
        # Perform user-based analysis
        user_based_threats = self._analyze_user_patterns(logs)
        threats.extend(user_based_threats)
        
        return threats
    
    def _is_threat_anomaly(self, threat_type, count, total_logs):
        """Determine if the occurrence of a threat type is anomalous"""
        # Simple threshold-based approach - in a real system, use more sophisticated anomaly detection
        thresholds = {
            'authentication_failure': 0.1,  # 10% of logs are authentication failures
            'privilege_escalation': 0.05,   # 5% of logs are privilege escalation
            'unusual_access': 0.05,
            'malware_activity': 0.02,
            'data_exfiltration': 0.03,
            'system_change': 0.08
        }
        
        threshold = thresholds.get(threat_type, 0.05)
        ratio = count / total_logs
        
        return ratio > threshold
    
    def _create_threat_from_logs(self, threat_type, source, logs, count):
        """Create a Threat object from log analysis"""
        # Get logs matching the threat type
        matching_logs = []
        for log in logs:
            if self.compiled_patterns[threat_type].search(log.message):
                matching_logs.append(log)
        
        if not matching_logs:
            return None
        
        # Determine severity based on count and log severity
        severity_counts = Counter([log.severity for log in matching_logs])
        dominant_severity = severity_counts.most_common(1)[0][0]
        
        # Map log severity to threat severity
        severity_map = {
            'critical': 'critical',
            'error': 'high',
            'warning': 'medium',
            'info': 'low'
        }
        
        severity = severity_map.get(dominant_severity, 'medium')
        
        # Increase severity if many occurrences
        if count > 50:
            severity = 'critical'
        elif count > 20:
            severity = 'high'
        
        # Extract unique IPs from logs if available
        ip_addresses = set()
        for log in matching_logs:
            if log.ip_address:
                ip_addresses.add(log.ip_address)
        
        source_ip = next(iter(ip_addresses)) if ip_addresses else None
        
        # Map threat type to a readable name
        threat_names = {
            'authentication_failure': 'Multiple Authentication Failures',
            'privilege_escalation': 'Privilege Escalation Attempt',
            'unusual_access': 'Unusual Access Pattern',
            'malware_activity': 'Potential Malware Activity',
            'data_exfiltration': 'Possible Data Exfiltration',
            'system_change': 'Unauthorized System Changes'
        }
        
        threat_name = threat_names.get(threat_type, 'Security Anomaly')
        
        # Create threat object
        threat = Threat(
            name=threat_name,
            description=f"Log analysis detected {count} instances of {threat_type.replace('_', ' ')} in {source} logs",
            threat_type=threat_type,
            severity=severity,
            confidence=self._calculate_confidence(count, len(logs), threat_type),
            status='active',
            source_ip=source_ip,
            attack_vector='Log-based detection'
        )
        
        # Set threat indicators
        indicators = {
            'log_count': count,
            'log_source': source,
            'unique_ips': len(ip_addresses),
            'time_range': f"{(logs[0].timestamp - logs[-1].timestamp).total_seconds() / 3600:.1f} hours"
        }
        
        threat.set_indicators(indicators)
        
        return threat
    
    def _analyze_time_patterns(self, logs):
        """Analyze temporal patterns in logs to detect anomalies"""
        threats = []
        
        # Group logs by hour
        hours = defaultdict(int)
        for log in logs:
            hour = log.timestamp.hour
            hours[hour] += 1
        
        # Calculate average and standard deviation
        hour_counts = list(hours.values())
        if not hour_counts:
            return threats
        
        avg_count = np.mean(hour_counts)
        std_count = np.std(hour_counts)
        
        # Detect hours with abnormal activity (Z-score > 2)
        abnormal_hours = []
        for hour, count in hours.items():
            if count > 0 and std_count > 0:
                z_score = (count - avg_count) / std_count
                if z_score > 2:
                    abnormal_hours.append((hour, count, z_score))
        
        # If abnormal hours detected, create a threat
        if abnormal_hours:
            max_hour, max_count, max_z = max(abnormal_hours, key=lambda x: x[2])
            
            # Determine if the hour is outside business hours (simplified)
            is_business_hours = 9 <= max_hour <= 17
            
            # Create threat if activity is outside business hours or extremely anomalous
            if not is_business_hours or max_z > 3:
                threat = Threat(
                    name="Unusual Temporal Activity Pattern",
                    description=f"Abnormal log activity detected during hour {max_hour}:00 with {max_count} logs",
                    threat_type="unusual_activity_pattern",
                    severity="medium" if is_business_hours else "high",
                    confidence=min(0.5 + (max_z / 10), 0.95),
                    status="active",
                    attack_vector="Temporal anomaly detection"
                )
                
                # Set indicators
                indicators = {
                    'anomalous_hour': max_hour,
                    'log_count': max_count,
                    'z_score': float(max_z),
                    'is_business_hours': is_business_hours
                }
                
                threat.set_indicators(indicators)
                threats.append(threat)
        
        return threats
    
    def _analyze_user_patterns(self, logs):
        """Analyze user patterns in logs to detect anomalies"""
        threats = []
        
        # Group logs by user
        user_logs = defaultdict(list)
        for log in logs:
            if log.user_id:
                user_logs[log.user_id].append(log)
        
        # Analyze each user's activity
        for user_id, user_logs_list in user_logs.items():
            # Count different log types
            log_types = Counter([log.log_type for log in user_logs_list])
            
            # Check for suspicious patterns
            auth_failures = log_types.get('login_failed', 0)
            
            # Multiple authentication failures
            if auth_failures > 5:
                threat = Threat(
                    name="Multiple Authentication Failures",
                    description=f"User ID {user_id} had {auth_failures} failed login attempts",
                    threat_type="brute_force",
                    severity="high" if auth_failures > 10 else "medium",
                    confidence=min(0.6 + (auth_failures / 20), 0.95),
                    status="active",
                    attack_vector="Authentication brute force"
                )
                
                # Set indicators
                indicators = {
                    'user_id': user_id,
                    'failed_attempts': auth_failures,
                    'time_period': f"{(user_logs_list[0].timestamp - user_logs_list[-1].timestamp).total_seconds() / 60:.1f} minutes"
                }
                
                threat.set_indicators(indicators)
                threats.append(threat)
        
        return threats
    
    def _calculate_confidence(self, count, total, threat_type):
        """Calculate confidence score for a detected threat"""
        # Base confidence based on frequency
        base_confidence = min(count / total * 5, 0.9)
        
        # Adjust based on threat type
        type_adjustments = {
            'authentication_failure': 0.05,
            'privilege_escalation': 0.1,
            'unusual_access': 0.05,
            'malware_activity': 0.15,
            'data_exfiltration': 0.1,
            'system_change': 0.0
        }
        
        adjustment = type_adjustments.get(threat_type, 0.0)
        
        return min(base_confidence + adjustment, 0.95)
    
    def save_threats_to_database(self, threats):
        """Save detected threats to the database and create alerts"""
        saved_threats = []
        
        for threat in threats:
            # Add threat to database
            db.session.add(threat)
            db.session.flush()  # Get ID without committing
            
            # Create an alert for the threat
            alert = Alert(
                title=f"New {threat.severity} threat detected: {threat.name}",
                description=threat.description,
                priority=threat.severity,
                status="new",
                threat_id=threat.id
            )
            
            db.session.add(alert)
            saved_threats.append(threat)
        
        # Commit all changes
        db.session.commit()
        
        return saved_threats

# Create analyzer instance
log_analyzer = LogAnalyzer()

def analyze_recent_logs():
    """Analyze recent logs and save detected threats to the database"""
    threats = log_analyzer.analyze_logs(time_range='24h')
    saved_threats = log_analyzer.save_threats_to_database(threats)
    
    return saved_threats

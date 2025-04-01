from flask import Blueprint, render_template, jsonify, request, flash, redirect, url_for
from flask_login import login_required, current_user
from app import db
from models import Threat, Alert, Log, SecurityRule
from datetime import datetime, timedelta
import json
import random
import numpy as np
from ml_models.threat_classifier import ThreatClassifier
from ml_models.anomaly_detector import AnomalyDetector
import logging

threat_bp = Blueprint('threat', __name__)
logger = logging.getLogger(__name__)

# Initialize ML models
threat_classifier = ThreatClassifier()
anomaly_detector = AnomalyDetector()

@threat_bp.route('/api/scan/network', methods=['POST'])
@login_required
def scan_network():
    """Initiates a network scan to detect potential threats"""
    try:
        # In a real system, this would connect to actual network monitoring tools
        # For this demo, we'll simulate finding threats
        
        scan_type = request.form.get('scan_type', 'quick')
        target_ip = request.form.get('target_ip', 'all')
        
        # Log the scan initiation
        log = Log(
            source="threat_detection",
            log_type="network_scan",
            message=f"Network scan initiated: {scan_type} scan on {target_ip}",
            user_id=current_user.id,
            severity="info"
        )
        db.session.add(log)
        db.session.commit()
        
        # Simulate finding threats
        threats_found = simulate_threat_detection(scan_type, target_ip)
        
        # Add detected threats to the database
        for threat_data in threats_found:
            # Check if this threat already exists
            existing_threat = Threat.query.filter_by(
                name=threat_data['name'],
                source_ip=threat_data['source_ip'],
                date_detected=datetime.utcnow().date()
            ).first()
            
            if not existing_threat:
                threat = Threat(
                    name=threat_data['name'],
                    description=threat_data['description'],
                    threat_type=threat_data['threat_type'],
                    severity=threat_data['severity'],
                    confidence=threat_data['confidence'],
                    status='active',
                    source_ip=threat_data['source_ip'],
                    destination_ip=threat_data.get('destination_ip'),
                    port=threat_data.get('port'),
                    protocol=threat_data.get('protocol'),
                    attack_vector=threat_data.get('attack_vector')
                )
                
                # Add indicators
                if 'indicators' in threat_data:
                    threat.set_indicators(threat_data['indicators'])
                
                db.session.add(threat)
                db.session.commit()
                
                # Create alert for the new threat
                alert = Alert(
                    title=f"New {threat_data['severity']} threat detected: {threat_data['name']}",
                    description=f"A new {threat_data['severity']} threat was detected during {scan_type} scan. "
                                f"Source IP: {threat_data['source_ip']}",
                    priority=threat_data['severity'],
                    status='new',
                    threat_id=threat.id,
                    user_id=current_user.id
                )
                db.session.add(alert)
                db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Scan completed. {len(threats_found)} potential threats detected.',
            'threats_count': len(threats_found),
            'threats': [{'name': t['name'], 'severity': t['severity']} for t in threats_found]
        })
    
    except Exception as e:
        logger.error(f"Error in network scan: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Error during network scan: {str(e)}'
        }), 500

@threat_bp.route('/api/scan/log-analysis', methods=['POST'])
@login_required
def analyze_logs():
    """Analyzes security logs to identify potential threats"""
    try:
        log_source = request.form.get('log_source', 'all')
        time_range = request.form.get('time_range', '24h')
        
        # Log the analysis initiation
        log = Log(
            source="threat_detection",
            log_type="log_analysis",
            message=f"Log analysis initiated for {log_source} logs over past {time_range}",
            user_id=current_user.id,
            severity="info"
        )
        db.session.add(log)
        db.session.commit()
        
        # Simulate log analysis and threat detection
        # In a real system, this would analyze actual logs
        threats_found = simulate_log_analysis(log_source, time_range)
        
        # Add detected threats to the database
        for threat_data in threats_found:
            threat = Threat(
                name=threat_data['name'],
                description=threat_data['description'],
                threat_type=threat_data['threat_type'],
                severity=threat_data['severity'],
                confidence=threat_data['confidence'],
                status='active',
                source_ip=threat_data.get('source_ip'),
                attack_vector=threat_data.get('attack_vector', 'log-based-detection')
            )
            
            if 'indicators' in threat_data:
                threat.set_indicators(threat_data['indicators'])
            
            db.session.add(threat)
            db.session.commit()
            
            # Create alert for the new threat
            alert = Alert(
                title=f"New {threat_data['severity']} threat detected from logs: {threat_data['name']}",
                description=f"A new {threat_data['severity']} threat was detected during log analysis. "
                            f"Source: {log_source}, Time range: {time_range}",
                priority=threat_data['severity'],
                status='new',
                threat_id=threat.id,
                user_id=current_user.id
            )
            db.session.add(alert)
            db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Log analysis completed. {len(threats_found)} potential threats detected.',
            'threats_count': len(threats_found),
            'threats': [{'name': t['name'], 'severity': t['severity']} for t in threats_found]
        })
    
    except Exception as e:
        logger.error(f"Error in log analysis: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Error during log analysis: {str(e)}'
        }), 500

@threat_bp.route('/threat/<int:threat_id>')
@login_required
def threat_details(threat_id):
    """View details of a specific threat"""
    threat = Threat.query.get_or_404(threat_id)
    
    # Get related alerts
    alerts = Alert.query.filter_by(threat_id=threat_id).all()
    
    # Get remediation actions
    remediation_actions = threat.remediation_actions.all()
    
    return render_template('threat_details.html', 
                          threat=threat,
                          alerts=alerts,
                          remediation_actions=remediation_actions,
                          indicators=threat.get_indicators(),
                          title=f'Threat: {threat.name}')

@threat_bp.route('/api/threat/<int:threat_id>/update-status', methods=['POST'])
@login_required
def update_threat_status(threat_id):
    """Update the status of a threat"""
    threat = Threat.query.get_or_404(threat_id)
    
    new_status = request.form.get('status')
    if not new_status or new_status not in ['active', 'investigating', 'remediated', 'false_positive']:
        return jsonify({
            'success': False,
            'message': 'Invalid status value'
        }), 400
    
    # Update the threat status
    old_status = threat.status
    threat.status = new_status
    threat.date_updated = datetime.utcnow()
    db.session.commit()
    
    # Log the status change
    log = Log(
        source="threat_management",
        log_type="status_change",
        message=f"Threat status updated from {old_status} to {new_status} for threat ID {threat_id}",
        user_id=current_user.id,
        severity="info"
    )
    db.session.add(log)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': f'Threat status updated to {new_status}'
    })

@threat_bp.route('/api/rules', methods=['GET'])
@login_required
def get_security_rules():
    """Get all security rules"""
    rules = SecurityRule.query.all()
    return jsonify({
        'success': True,
        'rules': [{
            'id': rule.id,
            'name': rule.name,
            'description': rule.description,
            'pattern': rule.pattern,
            'severity': rule.severity,
            'status': rule.status
        } for rule in rules]
    })

@threat_bp.route('/api/rules/add', methods=['POST'])
@login_required
def add_security_rule():
    """Add a new security rule"""
    try:
        name = request.form.get('name')
        description = request.form.get('description')
        pattern = request.form.get('pattern')
        severity = request.form.get('severity', 'medium')
        
        if not all([name, pattern]):
            return jsonify({
                'success': False,
                'message': 'Name and pattern are required'
            }), 400
        
        # Create new rule
        rule = SecurityRule(
            name=name,
            description=description,
            pattern=pattern,
            severity=severity,
            status='active'
        )
        
        db.session.add(rule)
        db.session.commit()
        
        # Log the rule creation
        log = Log(
            source="threat_management",
            log_type="rule_created",
            message=f"New security rule created: {name}",
            user_id=current_user.id,
            severity="info"
        )
        db.session.add(log)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Security rule created successfully',
            'rule_id': rule.id
        })
    
    except Exception as e:
        logger.error(f"Error creating security rule: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Error creating security rule: {str(e)}'
        }), 500

# Simulation functions for demo purposes
def simulate_threat_detection(scan_type, target_ip):
    """Simulate finding threats during a network scan"""
    # In a real system, this would use actual network scanning tools
    
    # Initialize the threat list
    threats = []
    
    # Threat types to randomly select from
    threat_types = [
        'malware', 'ransomware', 'ddos', 'intrusion', 'port_scan', 
        'brute_force', 'backdoor', 'sql_injection', 'xss', 'data_exfiltration'
    ]
    
    # Generate random number of threats based on scan type
    if scan_type == 'quick':
        num_threats = random.randint(0, 3)
    elif scan_type == 'deep':
        num_threats = random.randint(2, 7)
    else:  # comprehensive
        num_threats = random.randint(5, 12)
    
    # Generate random IP addresses
    ip_prefixes = ['192.168.1.', '10.0.0.', '172.16.0.']
    
    for _ in range(num_threats):
        # Select random threat characteristics
        threat_type = random.choice(threat_types)
        severity_options = ['low', 'medium', 'high', 'critical']
        severity_weights = [0.4, 0.3, 0.2, 0.1]  # Make critical less common
        severity = random.choices(severity_options, weights=severity_weights)[0]
        
        # Generate random IPs
        source_ip = random.choice(ip_prefixes) + str(random.randint(1, 254))
        dest_ip = random.choice(ip_prefixes) + str(random.randint(1, 254))
        
        # Create threat data
        threat_data = {
            'name': f"{threat_type.capitalize()} attack detected",
            'description': generate_threat_description(threat_type, severity),
            'threat_type': threat_type,
            'severity': severity,
            'confidence': round(random.uniform(0.65, 0.98), 2),
            'source_ip': source_ip,
            'destination_ip': dest_ip,
            'port': random.randint(1, 65535),
            'protocol': random.choice(['TCP', 'UDP', 'HTTP', 'HTTPS', 'FTP']),
            'attack_vector': generate_attack_vector(threat_type),
            'indicators': generate_indicators(threat_type)
        }
        
        # Apply machine learning classification (simulated)
        features = extract_features(threat_data)
        ml_classification = threat_classifier.classify(features)
        
        # Update threat data with ML results
        if ml_classification['confidence'] > threat_data['confidence']:
            threat_data['severity'] = ml_classification['severity']
            threat_data['confidence'] = ml_classification['confidence']
        
        threats.append(threat_data)
    
    return threats

def simulate_log_analysis(log_source, time_range):
    """Simulate finding threats during log analysis"""
    # In a real system, this would analyze actual log files
    
    # Initialize threat list
    threats = []
    
    # Log-based threat types
    log_threat_types = [
        'authentication_failure', 'privilege_escalation', 'unusual_access_pattern',
        'configuration_change', 'suspicious_command', 'policy_violation'
    ]
    
    # Generate random number of threats
    if time_range == '1h':
        num_threats = random.randint(0, 2)
    elif time_range == '24h':
        num_threats = random.randint(1, 4)
    else:  # 7d
        num_threats = random.randint(3, 8)
    
    for _ in range(num_threats):
        # Select random threat characteristics
        threat_type = random.choice(log_threat_types)
        severity_options = ['low', 'medium', 'high', 'critical']
        severity_weights = [0.35, 0.35, 0.2, 0.1]  # Distribute severity
        severity = random.choices(severity_options, weights=severity_weights)[0]
        
        # Generate random source IP for the log entry
        source_ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
        
        # Create threat data
        threat_data = {
            'name': f"{threat_type.replace('_', ' ').title()} detected",
            'description': generate_log_threat_description(threat_type, log_source),
            'threat_type': threat_type,
            'severity': severity,
            'confidence': round(random.uniform(0.7, 0.95), 2),
            'source_ip': source_ip,
            'indicators': generate_log_indicators(threat_type, log_source)
        }
        
        # Apply anomaly detection (simulated)
        features = extract_log_features(threat_data)
        anomaly_result = anomaly_detector.detect_anomaly(features)
        
        # Update threat data with anomaly detection results
        if anomaly_result['is_anomaly'] and anomaly_result['confidence'] > threat_data['confidence']:
            threat_data['severity'] = 'high' if anomaly_result['confidence'] > 0.9 else threat_data['severity']
            threat_data['confidence'] = anomaly_result['confidence']
        
        threats.append(threat_data)
    
    return threats

def generate_threat_description(threat_type, severity):
    """Generate a realistic description for a threat"""
    if threat_type == 'malware':
        return f"Potential {severity} severity malware activity detected. The system has identified suspicious executable behavior consistent with known malware patterns."
    elif threat_type == 'ransomware':
        return f"Possible {severity} ransomware activity detected. Unusual file encryption operations observed with potential ransom behavior."
    elif threat_type == 'ddos':
        return f"Distributed Denial of Service ({severity}) attack detected. Abnormal traffic volume targeting network resources."
    elif threat_type == 'intrusion':
        return f"Network intrusion attempt ({severity}) detected. Unauthorized access patterns observed from external source."
    elif threat_type == 'port_scan':
        return f"{severity.capitalize()} port scanning activity detected. Sequential connection attempts to multiple ports indicate reconnaissance."
    elif threat_type == 'brute_force':
        return f"{severity.capitalize()} brute force attack detected. Multiple failed authentication attempts observed."
    elif threat_type == 'backdoor':
        return f"Potential {severity} backdoor activity detected. Suspicious outbound connection with unusual persistence pattern."
    elif threat_type == 'sql_injection':
        return f"{severity.capitalize()} SQL injection attempt detected. Malformed database queries with injection patterns observed."
    elif threat_type == 'xss':
        return f"{severity.capitalize()} Cross-site scripting (XSS) attempt detected. Suspicious script injection in web requests."
    elif threat_type == 'data_exfiltration':
        return f"{severity.capitalize()} data exfiltration activity detected. Unusual outbound data transfer patterns observed."
    else:
        return f"{severity.capitalize()} security threat detected. Unusual activity requires investigation."

def generate_log_threat_description(threat_type, log_source):
    """Generate a realistic description for a log-based threat"""
    if threat_type == 'authentication_failure':
        return f"Multiple failed authentication attempts detected in {log_source} logs. Potential brute force attack in progress."
    elif threat_type == 'privilege_escalation':
        return f"Suspicious privilege escalation activity observed in {log_source} logs. User attempting to gain elevated system access."
    elif threat_type == 'unusual_access_pattern':
        return f"Unusual access pattern detected in {log_source} logs. Access to sensitive resources outside normal usage patterns."
    elif threat_type == 'configuration_change':
        return f"Unauthorized configuration change detected in {log_source} logs. Critical system settings modified outside change control process."
    elif threat_type == 'suspicious_command':
        return f"Suspicious command execution detected in {log_source} logs. Potentially malicious commands observed."
    elif threat_type == 'policy_violation':
        return f"Security policy violation detected in {log_source} logs. User actions violate defined security policies."
    else:
        return f"Suspicious activity detected in {log_source} logs. Requires further investigation."

def generate_attack_vector(threat_type):
    """Generate a plausible attack vector based on threat type"""
    vectors = {
        'malware': "Email attachment",
        'ransomware': "Phishing email",
        'ddos': "Botnet",
        'intrusion': "Exploited vulnerability",
        'port_scan': "Network reconnaissance",
        'brute_force': "Password attack",
        'backdoor': "Compromised application",
        'sql_injection': "Web application vulnerability",
        'xss': "Malicious script injection",
        'data_exfiltration': "Compromised credentials"
    }
    
    return vectors.get(threat_type, "Unknown vector")

def generate_indicators(threat_type):
    """Generate threat indicators based on threat type"""
    indicators = {
        'suspicious_processes': random.randint(1, 5),
        'network_connections': random.randint(2, 10),
        'file_modifications': random.randint(0, 20),
        'registry_changes': random.randint(0, 8)
    }
    
    # Add threat-specific indicators
    if threat_type == 'malware':
        indicators['signature_matches'] = random.randint(1, 3)
    elif threat_type == 'ransomware':
        indicators['encrypted_files'] = random.randint(10, 100)
    elif threat_type == 'ddos':
        indicators['packets_per_second'] = random.randint(1000, 10000)
    elif threat_type == 'brute_force':
        indicators['login_attempts'] = random.randint(20, 100)
    
    return indicators

def generate_log_indicators(threat_type, log_source):
    """Generate log-based threat indicators"""
    # Base indicators present in most log-based threats
    indicators = {
        'event_count': random.randint(5, 50),
        'timespan_minutes': random.randint(1, 60),
        'unique_users': random.randint(1, 3)
    }
    
    # Add threat-specific indicators
    if threat_type == 'authentication_failure':
        indicators['failed_attempts'] = random.randint(10, 30)
        indicators['unique_ips'] = random.randint(1, 5)
    elif threat_type == 'privilege_escalation':
        indicators['permission_changes'] = random.randint(1, 5)
        indicators['sudo_commands'] = random.randint(3, 10)
    elif threat_type == 'unusual_access_pattern':
        indicators['accessed_files'] = random.randint(5, 20)
        indicators['access_time'] = "Outside business hours"
    
    return indicators

def extract_features(threat_data):
    """Extract features from threat data for ML classification"""
    # In a real implementation, this would extract actual features
    # For this demo, we'll create synthetic features
    
    # Convert categorical features to numeric
    threat_type_map = {
        'malware': 1, 'ransomware': 2, 'ddos': 3, 'intrusion': 4, 'port_scan': 5,
        'brute_force': 6, 'backdoor': 7, 'sql_injection': 8, 'xss': 9, 'data_exfiltration': 10
    }
    
    protocol_map = {'TCP': 1, 'UDP': 2, 'HTTP': 3, 'HTTPS': 4, 'FTP': 5}
    
    # Create feature vector
    features = [
        threat_type_map.get(threat_data['threat_type'], 0),
        threat_data['confidence'],
        threat_data['port'] / 65535,  # Normalize port number
        protocol_map.get(threat_data['protocol'], 0),
        len(threat_data['indicators'])
    ]
    
    return np.array(features).reshape(1, -1)

def extract_log_features(threat_data):
    """Extract features from log data for anomaly detection"""
    # For this demo, we'll create synthetic features
    
    # Convert categorical features to numeric
    threat_type_map = {
        'authentication_failure': 1, 'privilege_escalation': 2, 
        'unusual_access_pattern': 3, 'configuration_change': 4,
        'suspicious_command': 5, 'policy_violation': 6
    }
    
    # Extract numeric features from indicators
    indicators = threat_data['indicators']
    event_count = indicators.get('event_count', 0)
    timespan = indicators.get('timespan_minutes', 0)
    unique_users = indicators.get('unique_users', 1)
    
    # Create feature vector
    features = [
        threat_type_map.get(threat_data['threat_type'], 0),
        threat_data['confidence'],
        event_count,
        timespan,
        unique_users,
        event_count / max(timespan, 1)  # Events per minute
    ]
    
    return np.array(features).reshape(1, -1)

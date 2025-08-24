import os
import logging
import random
import json
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user, login_required
from sqlalchemy.orm import DeclarativeBase
from datetime import datetime, timedelta


# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize database
class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

# Import configuration
from config import config

# Create Flask app
app = Flask(__name__)

# Load configuration - use 'xampp' for XAMPP with MySQL, 'development' for SQLite
config_name = os.environ.get('FLASK_CONFIG', 'development')
app.config.from_object(config[config_name])

# Add additional database options
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Initialize database with app
db.init_app(app)

# Configure login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'
login_manager.login_message_category = 'info'

# Import models after db initialization to avoid circular imports
with app.app_context():
    import models
    from auth import auth_bp
    from threat_detection import threat_bp
    from remediation import remediation_bp
    
    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(threat_bp)
    app.register_blueprint(remediation_bp)
    
    # Create all database tables
    db.create_all()

# Import user loader
@login_manager.user_loader
def load_user(user_id):
    return models.User.query.get(int(user_id))

# Define routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('auth.login'))

@app.route('/dashboard')
def dashboard():
    if not current_user.is_authenticated:
        return redirect(url_for('auth.login'))
    
    # Get recent threats and alerts for dashboard
    threats = models.Threat.query.order_by(models.Threat.date_detected.desc()).limit(5).all()
    alerts = models.Alert.query.order_by(models.Alert.date_created.desc()).limit(10).all()
    
    # Get threat statistics for charts
    threat_stats = models.Threat.query.with_entities(
        models.Threat.severity, 
        db.func.count(models.Threat.id)
    ).group_by(models.Threat.severity).all()
    
    stats = {
        'total_threats': models.Threat.query.count(),
        'critical_threats': models.Threat.query.filter_by(severity='critical').count(),
        'high_threats': models.Threat.query.filter_by(severity='high').count(),
        'medium_threats': models.Threat.query.filter_by(severity='medium').count(),
        'low_threats': models.Threat.query.filter_by(severity='low').count(),
        'remediated_threats': models.Threat.query.filter_by(status='remediated').count()
    }
    
    # Check if we have any prediction results in the session
    prediction_results = session.get('prediction_results', None)
    # Clear the session after retrieving data to prevent stale results
    if prediction_results:
        session.pop('prediction_results', None)
    
    return render_template('dashboard.html', 
                          threats=threats, 
                          alerts=alerts, 
                          threat_stats=threat_stats,
                          stats=stats,
                          prediction_results=prediction_results,
                          title='Security Dashboard')

@app.route('/threats')
def threats():
    if not current_user.is_authenticated:
        return redirect(url_for('auth.login'))
    
    page = request.args.get('page', 1, type=int)
    threats = models.Threat.query.order_by(models.Threat.date_detected.desc())\
        .paginate(page=page, per_page=10)
    
    return render_template('threats.html', threats=threats, title='Threat Management')

@app.route('/logs')
def logs():
    if not current_user.is_authenticated:
        return redirect(url_for('auth.login'))
    
    page = request.args.get('page', 1, type=int)
    logs = models.Log.query.order_by(models.Log.timestamp.desc())\
        .paginate(page=page, per_page=20)
    
    return render_template('logs.html', logs=logs, title='Security Logs')

@app.route('/settings')
def settings():
    if not current_user.is_authenticated:
        return redirect(url_for('auth.login'))
    
    # Get system settings or use default values
    system_settings = {
        'scan_frequency': 'daily',
        'threat_sensitivity': 'medium',
        'auto_remediation': False,
        'notification_email': current_user.email if current_user.is_authenticated else ''
    }
    
    # Get actual settings from database if available
    db_settings = models.SystemSettings.query.all()
    for setting in db_settings:
        system_settings[setting.setting_name] = setting.setting_value
    
    return render_template('settings.html', 
                          title='System Settings', 
                          system_settings=system_settings,
                          timedelta=timedelta)

@app.route('/profile')
def profile():
    if not current_user.is_authenticated:
        return redirect(url_for('auth.login'))
    
    return render_template('profile.html', title='User Profile')

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

# API endpoints for AJAX requests
@app.route('/api/threats/summary')
def threat_summary():
    if not current_user.is_authenticated:
        return jsonify({'error': 'Authentication required'}), 401
    
    # Get threat summary data for charts
    threat_counts = {
        'critical': models.Threat.query.filter_by(severity='critical').count(),
        'high': models.Threat.query.filter_by(severity='high').count(),
        'medium': models.Threat.query.filter_by(severity='medium').count(),
        'low': models.Threat.query.filter_by(severity='low').count()
    }
    
    # Get threat status data
    status_counts = {
        'active': models.Threat.query.filter_by(status='active').count(),
        'investigating': models.Threat.query.filter_by(status='investigating').count(),
        'remediated': models.Threat.query.filter_by(status='remediated').count(),
        'false_positive': models.Threat.query.filter_by(status='false_positive').count()
    }
    
    # Get threat types data
    type_counts = db.session.query(
        models.Threat.threat_type, 
        db.func.count(models.Threat.id)
    ).group_by(models.Threat.threat_type).all()
    
    type_data = {t_type: count for t_type, count in type_counts}
    
    return jsonify({
        'by_severity': threat_counts,
        'by_status': status_counts,
        'by_type': type_data
    })

# Threat prediction route
@app.route('/predict_threats', methods=['POST'])
@login_required
def predict_threats():
    """Generate threat predictions based on the provided parameters"""
    try:
        # Get prediction parameters from the form
        prediction_type = request.form.get('prediction_type', 'threat_likelihood')
        time_frame = request.form.get('time_frame', '24h')
        
        # Handle custom timeframe
        if time_frame == 'custom':
            custom_days = request.form.get('custom_timeframe', '14')
            try:
                custom_days = int(custom_days)
                if custom_days < 1:
                    custom_days = 14
                elif custom_days > 365:
                    custom_days = 365
                time_frame = f"{custom_days}d"
            except ValueError:
                time_frame = '14d'
        
        data_sources = request.form.getlist('data_sources[]')
        specific_threats = request.form.get('specific_threats', '')
        confidence_threshold = int(request.form.get('confidence_threshold', 70))
        
        # Log the prediction request
        log = models.Log(
            source="prediction",
            log_type="threat_prediction",
            message=f"Threat prediction requested: Type={prediction_type}, Time Frame={time_frame}",
            user_id=current_user.id if current_user.is_authenticated else None,
            severity="info"
        )
        db.session.add(log)
        db.session.commit()
        
        # In a real system, we would use the threat_classifier and anomaly_detector ML models
        # For now, we'll simulate results based on the parameters
        
        # Import classifier and detector from threat_detection.py
        from threat_detection import threat_classifier, anomaly_detector
        
        # Generate prediction results based on type
        prediction_results = generate_prediction_results(
            prediction_type, 
            time_frame, 
            data_sources, 
            confidence_threshold
        )
        
        # Store results in session for the dashboard to display
        session['prediction_results'] = prediction_results
        
        flash('Threat prediction generated successfully', 'success')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        logger.error(f"Error generating threat prediction: {str(e)}")
        flash(f'An error occurred while generating prediction: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

def generate_prediction_results(prediction_type, time_frame, data_sources, confidence_threshold, specific_threats=None):
    """Generate simulated prediction results based on parameters"""
    # Base score based on confidence threshold
    base_score = confidence_threshold
    # Adjust score randomly to simulate variance
    score = max(50, min(95, base_score + random.randint(-10, 10)))
    
    # Define title and description based on prediction type
    prediction_titles = {
        'threat_likelihood': 'Threat Likelihood Analysis',
        'attack_vector': 'Attack Vector Analysis',
        'vulnerability_assessment': 'Vulnerability Assessment',
        'security_posture': 'Security Posture Forecast'
    }
    
    prediction_descriptions = {
        'threat_likelihood': 'Prediction of potential threats based on historical data and threat intelligence',
        'attack_vector': 'Analysis of potential attack vectors and entry points',
        'vulnerability_assessment': 'Assessment of system vulnerabilities and exploitation risks',
        'security_posture': 'Overall security posture and recommendations'
    }
    
    # Generate color based on score
    if score >= 80:
        color = 'bg-danger'
    elif score >= 60:
        color = 'bg-warning'
    else:
        color = 'bg-success'
    
    # Generate list of potential threats
    common_threats = [
        {"name": "SQL Injection Attack", "probability": random.randint(60, 90), "badge_class": "bg-danger"},
        {"name": "Cross-Site Scripting (XSS)", "probability": random.randint(55, 85), "badge_class": "bg-warning text-dark"},
        {"name": "Brute Force Authentication", "probability": random.randint(50, 80), "badge_class": "bg-danger"},
        {"name": "DDoS Attack", "probability": random.randint(40, 75), "badge_class": "bg-warning text-dark"},
        {"name": "Phishing Campaign", "probability": random.randint(60, 85), "badge_class": "bg-danger"},
        {"name": "Malware Infection", "probability": random.randint(50, 80), "badge_class": "bg-warning text-dark"},
        {"name": "Credential Stuffing", "probability": random.randint(45, 75), "badge_class": "bg-info text-dark"},
        {"name": "Insider Threat", "probability": random.randint(30, 65), "badge_class": "bg-info text-dark"}
    ]
    
    # Filter threats based on specific_threats parameter if provided
    if specific_threats:
        # Split comma-separated string into list of threats
        threat_names = [t.strip().lower() for t in specific_threats.split(',') if t.strip()]
        
        if threat_names:
            # Filter threats that match or partially match the provided names
            filtered_threats = []
            for threat in common_threats:
                for name in threat_names:
                    if name in threat['name'].lower():
                        # Boost the probability for specifically requested threats
                        threat['probability'] = min(95, threat['probability'] + 10)
                        filtered_threats.append(threat)
                        break
            
            # If we found matching threats, use them
            if filtered_threats:
                common_threats = filtered_threats
    
    # Select a subset of threats based on prediction type and sort by probability
    selected_threats = sorted(
        random.sample(common_threats, k=min(4, len(common_threats))),
        key=lambda x: x["probability"],
        reverse=True
    )
    
    # Generate recommendations based on prediction type
    recommendation_options = {
        'threat_likelihood': [
            "Implement multi-factor authentication across all systems",
            "Update firewall rules to block suspicious IP ranges",
            "Conduct security awareness training for all employees",
            "Review and update access control policies"
        ],
        'attack_vector': [
            "Implement web application firewall for public-facing services",
            "Secure API endpoints with rate limiting and IP restrictions",
            "Enforce HTTPS across all web services",
            "Implement network segmentation to isolate critical systems"
        ],
        'vulnerability_assessment': [
            "Patch identified system vulnerabilities within 48 hours",
            "Implement regular vulnerability scanning schedule",
            "Review and harden server configurations",
            "Deploy intrusion detection systems on critical network segments"
        ],
        'security_posture': [
            "Develop and test incident response procedures",
            "Implement security monitoring and alerting",
            "Conduct regular security audits and penetration testing",
            "Review and update the security policy documentation"
        ]
    }
    
    # Select 3-4 recommendations
    recommendations = random.sample(
        recommendation_options.get(prediction_type, recommendation_options['threat_likelihood']),
        k=min(3, len(recommendation_options.get(prediction_type, [])))
    )
    
    # Prepare the final results object
    results = {
        'title': prediction_titles.get(prediction_type, 'Threat Analysis'),
        'description': prediction_descriptions.get(prediction_type, 'Analysis of potential security threats'),
        'score': score,
        'color': color,
        'threats': selected_threats,
        'recommendations': recommendations,
        'timestamp': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    return results

# Context processor for global template variables
@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

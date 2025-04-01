import os
import logging
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user
from sqlalchemy.orm import DeclarativeBase
from datetime import datetime


# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize database
class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-replace-in-production")

# Configure database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///cybersecurity.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

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
    
    return render_template('dashboard.html', 
                          threats=threats, 
                          alerts=alerts, 
                          threat_stats=threat_stats,
                          stats=stats,
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
    
    return render_template('settings.html', title='System Settings')

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

# Context processor for global template variables
@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

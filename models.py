from app import db
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import json

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    first_name = db.Column(db.String(64))
    last_name = db.Column(db.String(64))
    role = db.Column(db.String(20), default='analyst')
    date_registered = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationship with other models
    alerts = db.relationship('Alert', backref='user', lazy='dynamic')
    logs = db.relationship('Log', backref='user', lazy='dynamic')
    remediations = db.relationship('RemediationAction', backref='performed_by', lazy='dynamic')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'

class Threat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    threat_type = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    confidence = db.Column(db.Float, default=0.0)
    status = db.Column(db.String(20), default='active')
    source_ip = db.Column(db.String(50))
    destination_ip = db.Column(db.String(50))
    port = db.Column(db.Integer)
    protocol = db.Column(db.String(20))
    date_detected = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    attack_vector = db.Column(db.String(100))
    indicators = db.Column(db.Text)  # JSON serialized indicators
    
    # Relationships
    alerts = db.relationship('Alert', backref='threat', lazy='dynamic')
    remediation_actions = db.relationship('RemediationAction', backref='threat', lazy='dynamic')
    
    def set_indicators(self, indicators_dict):
        self.indicators = json.dumps(indicators_dict)
    
    def get_indicators(self):
        if self.indicators:
            return json.loads(self.indicators)
        return {}
    
    def __repr__(self):
        return f'<Threat {self.name}>'

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    priority = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default='new')
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    date_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Foreign keys
    threat_id = db.Column(db.Integer, db.ForeignKey('threat.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    def __repr__(self):
        return f'<Alert {self.title}>'

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    source = db.Column(db.String(50), nullable=False)
    log_type = db.Column(db.String(50), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(255))
    severity = db.Column(db.String(20), default='info')
    raw_data = db.Column(db.Text)
    
    # Foreign key to user
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    def __repr__(self):
        return f'<Log {self.id}: {self.log_type}>'

class RemediationAction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    action_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)
    date_performed = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')
    result = db.Column(db.Text)
    is_automated = db.Column(db.Boolean, default=False)
    details = db.Column(db.Text)  # JSON serialized details
    
    # Foreign keys
    threat_id = db.Column(db.Integer, db.ForeignKey('threat.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    def set_details(self, details_dict):
        self.details = json.dumps(details_dict)
    
    def get_details(self):
        if self.details:
            return json.loads(self.details)
        return {}
    
    def __repr__(self):
        return f'<RemediationAction {self.action_type}>'

class SystemSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    setting_name = db.Column(db.String(100), unique=True, nullable=False)
    setting_value = db.Column(db.Text)
    description = db.Column(db.Text)
    date_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<SystemSetting {self.setting_name}>'

class SecurityRule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    pattern = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), default='medium')
    status = db.Column(db.String(20), default='active')
    created_on = db.Column(db.DateTime, default=datetime.utcnow)
    updated_on = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<SecurityRule {self.name}>'

"""
Setup script for the AI-Powered Cyber Threat Detection System
This script helps to initialize the database and create initial user
"""

import os
import sys
from datetime import datetime
from werkzeug.security import generate_password_hash
from app import app, db
import models
from config import XAMPPConfig

def setup_database():
    """Setup the database and create initial data"""
    print("Setting up database...")
    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Check if admin user exists
        admin = models.User.query.filter_by(username='admin').first()
        if not admin:
            # Create admin user
            admin = models.User(
                username='admin',
                email='admin@example.com',
                password_hash=generate_password_hash('admin123'),
                first_name='Admin',
                last_name='User',
                role='admin',
                date_registered=datetime.utcnow(),
                is_active=True
            )
            db.session.add(admin)
            
            # Create sample system settings
            settings = [
                models.SystemSettings(setting_name='scan_frequency', setting_value='daily', 
                                     description='How often to perform automated scans'),
                models.SystemSettings(setting_name='threat_sensitivity', setting_value='medium', 
                                     description='Sensitivity level for threat detection'),
                models.SystemSettings(setting_name='auto_remediation', setting_value='False', 
                                     description='Whether to automatically apply remediation actions'),
                models.SystemSettings(setting_name='notification_email', setting_value='admin@example.com', 
                                     description='Email to send security notifications')
            ]
            db.session.add_all(settings)
            
            # Create sample security rule
            rule = models.SecurityRule(
                name='Suspicious Login Attempts',
                description='Detects multiple failed login attempts from the same IP address',
                pattern='failed_login_count > 5 AND time_period < 10 minutes',
                severity='high',
                status='active'
            )
            db.session.add(rule)
            
            # Commit the session
            db.session.commit()
            print("Created admin user and initial settings")
        else:
            print("Admin user already exists")

def configure_for_xampp():
    """Configure the application for XAMPP"""
    print("Configuring for XAMPP...")
    # Set environment variable for XAMPP config
    os.environ['FLASK_CONFIG'] = 'xampp'
    
    # Print the database URI being used
    print(f"Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")
    
    # Check if database settings need to be modified
    print("\nCurrent MySQL settings in config.py:")
    print(f"User: {XAMPPConfig.DB_USER}")
    print(f"Password: {'[empty]' if XAMPPConfig.DB_PASSWORD == '' else '[set]'}")
    print(f"Database: {XAMPPConfig.DB_NAME}")
    print(f"Host: {XAMPPConfig.DB_HOST}")
    
    print("\nMake sure to update these in config.py if they don't match your XAMPP setup.")

def print_instructions():
    """Print additional instructions"""
    print("\n=== Setup Complete ===")
    print("\nTo run the application:")
    print("1. Ensure XAMPP is running with MySQL service started")
    print("2. Set the environment variable: 'set FLASK_CONFIG=xampp' (Windows) or 'export FLASK_CONFIG=xampp' (Linux/Mac)")
    print("3. Run the application: 'python main.py'")
    print("4. Access the application at: http://localhost:5000")
    print("\nDefault login credentials:")
    print("Username: admin")
    print("Password: admin123")

if __name__ == "__main__":
    configure_for_xampp()
    setup_database()
    print_instructions()
"""
Configuration file for Cyber Threat Detection System
This file contains configuration settings for different environments
"""

import os

class Config:
    """Base configuration class with shared settings"""
    SECRET_KEY = os.environ.get('SESSION_SECRET', 'dev-secret-key-change-in-production')
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class DevelopmentConfig(Config):
    """Configuration for development environment"""
    DEBUG = True
    # SQLite database for development
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///cybersecurity.db')


class ProductionConfig(Config):
    """Configuration for production environment"""
    DEBUG = False
    # PostgreSQL for production
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'postgresql://user:password@localhost/cybersecurity')


class TestingConfig(Config):
    """Configuration for testing environment"""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'


class XAMPPConfig(Config):
    """Configuration for XAMPP environment with MySQL"""
    DEBUG = True
    # MySQL configuration for XAMPP
    # Change these values to match your XAMPP setup
    DB_USER = 'root'  # Default XAMPP MySQL username
    DB_PASSWORD = ''  # Default XAMPP MySQL password is empty
    DB_NAME = 'cybersecurity'  # Database name to create in phpMyAdmin
    DB_HOST = 'localhost'  # Default XAMPP host
    
    SQLALCHEMY_DATABASE_URI = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}"
    

# Dictionary of available configurations
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'xampp': XAMPPConfig,
    
    # Default configuration
    'default': DevelopmentConfig
}
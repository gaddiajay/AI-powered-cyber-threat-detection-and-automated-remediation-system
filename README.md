# AI-Powered Cyber Threat Detection and Automated Remediation System

A comprehensive cybersecurity platform that combines AI/ML techniques with security best practices to detect, analyze, and remediate cyber threats automatically.

## Project Overview

This system is designed as a final year college project to demonstrate the application of artificial intelligence and machine learning in cybersecurity. It provides real-time threat detection, analysis of security logs, prediction of potential threats, and automated remediation capabilities.

### Key Features

- **Dashboard with Security Metrics**: Real-time overview of security status with key metrics and charts
- **AI-Powered Threat Detection**: Machine learning models for detecting and classifying cybersecurity threats
- **Threat Prediction**: AI-based forecasting of potential security threats and vulnerabilities
- **Automated Log Analysis**: Intelligent analysis of security logs to identify anomalies and patterns
- **Remediation Workflow**: Structured approach to addressing and mitigating detected threats
- **User Authentication**: Secure login system with role-based access control
- **Customizable Security Rules**: Create and manage custom security detection rules

## Installation and Setup

### Prerequisites

- Python 3.8 or higher
- XAMPP with MySQL (for database)
- pip (Python package manager)

### Setup with XAMPP

1. **Clone the repository**
   ```
   git clone https://github.com/yourusername/cyber-threat-detection-system.git
   cd cyber-threat-detection-system
   ```

2. **Set up a virtual environment (optional but recommended)**
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```
   pip install -r requirements.txt
   ```

4. **MySQL Database Setup with XAMPP**
   - Start XAMPP Control Panel and ensure MySQL service is running
   - Open phpMyAdmin (http://localhost/phpmyadmin)
   - Create a new database named `cybersecurity`

5. **Configure the application**
   - Set the environment variable to use XAMPP configuration:
     ```
     set FLASK_CONFIG=xampp  # On Linux/Mac: export FLASK_CONFIG=xampp
     ```
   - Modify `config.py` file if your MySQL credentials are different from the defaults:
     ```python
     DB_USER = 'root'  # Change if needed
     DB_PASSWORD = ''  # Change if needed
     DB_NAME = 'cybersecurity'
     DB_HOST = 'localhost'
     ```

6. **Initialize the database**
   ```
   python main.py
   ```
   This will create all the necessary tables in your MySQL database.

7. **Run the application**
   ```
   python main.py
   ```
   The application should now be running at http://localhost:5000

### Default Login Credentials

- Username: admin
- Password: admin123

(Make sure to change these credentials in a production environment)

## System Architecture

### Components

- **Flask Web Framework**: Backend web application
- **SQLAlchemy ORM**: Database interactions
- **Machine Learning Models**: Threat classification and anomaly detection
- **Bootstrap UI**: Responsive user interface

### Models & AI Components

1. **Threat Classifier**: Machine learning model for classifying different types of cybersecurity threats
2. **Anomaly Detector**: Statistical and ML-based detection of unusual patterns in security data
3. **Predictive Analytics Engine**: Forecasting potential security issues based on historical data

## Usage Guide

### Dashboard

The dashboard provides an overview of the system's security status with:
- Threat summary statistics
- Recent alerts
- System status
- Predictive threat analysis

### Threat Detection

The system detects threats through:
- Network scanning
- Log analysis
- Behavior monitoring
- AI-based prediction

### Remediation

When a threat is detected:
1. The system evaluates its severity and impact
2. Suggests appropriate remediation actions
3. Can automatically implement certain security measures
4. Tracks the remediation progress

## License

This project is intended for educational purposes only. Please use responsibly and legally.

## Contributors

- Your Name
- (Add your team members here)

## Acknowledgments

- List any libraries, resources, or individuals that helped in creating this project
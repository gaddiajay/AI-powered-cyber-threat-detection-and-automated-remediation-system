# Running the Cyber Threat Detection System with XAMPP

This guide will help you set up and run the AI-Powered Cyber Threat Detection System using XAMPP for Windows.

## Prerequisites

1. XAMPP installed on your system (download from https://www.apachefriends.org/download.html)
2. Python 3.8 or higher installed
3. Basic knowledge of MySQL and Python

## Step 1: Install XAMPP

If you haven't already, download and install XAMPP from the official website. The default installation should be fine.

## Step 2: Start XAMPP Services

1. Open the XAMPP Control Panel
2. Start the Apache and MySQL services by clicking the "Start" buttons next to them
3. Verify they're running correctly (status should turn green)

## Step 3: Create the Database

1. Click on the "Admin" button next to MySQL in the XAMPP Control Panel, or go to http://localhost/phpmyadmin in your browser
2. In phpMyAdmin, click on "New" in the left sidebar
3. Enter "cybersecurity" as the database name and click "Create"

## Step 4: Prepare the Python Environment

1. Extract the AI-Powered Cyber Threat Detection System files to a directory of your choice
2. Open a command prompt and navigate to that directory
3. Create a virtual environment (recommended):
   ```
   python -m venv venv
   venv\Scripts\activate
   ```
4. Install the required dependencies:
   ```
   pip install Flask Flask-Login Flask-SQLAlchemy Flask-WTF Werkzeug SQLAlchemy email-validator WTForms pymysql numpy pandas scikit-learn joblib matplotlib plotly python-dotenv Jinja2 markupsafe
   ```

## Step 5: Configure the Application for XAMPP

1. Open the `config.py` file in a text editor
2. Locate the `XAMPPConfig` class and update the values if needed:
   ```python
   DB_USER = 'root'  # Default XAMPP MySQL username
   DB_PASSWORD = ''  # Default XAMPP MySQL password is empty
   DB_NAME = 'cybersecurity'  # Database name we created
   DB_HOST = 'localhost'  # Default XAMPP host
   ```
   
   If you set a password for your MySQL in XAMPP, update the `DB_PASSWORD` value accordingly.

3. Set the environment variable to use XAMPP configuration:
   ```
   set FLASK_CONFIG=xampp
   ```

## Step 6: Initialize the Database

1. Run the setup script to create tables and add initial data:
   ```
   python setup.py
   ```
   
   This script will:
   - Create all necessary database tables
   - Add an admin user
   - Set up initial system settings

## Step 7: Run the Application

1. Start the application:
   ```
   python main.py
   ```

2. Open your browser and go to:
   ```
   http://localhost:5000
   ```

3. Log in with the default credentials:
   - Username: admin
   - Password: admin123

## Troubleshooting

### Database Connection Issues

- Verify that MySQL is running in XAMPP Control Panel
- Check if the database "cybersecurity" exists in phpMyAdmin
- Ensure your database credentials in `config.py` match those in XAMPP

### Import Errors

- Make sure all dependencies are installed:
  ```
  pip install -r dependencies.txt
  ```

### Port Conflicts

- If port 5000 is already in use, modify the port in `main.py`:
  ```python
  app.run(host="0.0.0.0", port=5001, debug=True)
  ```

## Customizing the Application

### Changing the Admin Password

1. Log in with the default credentials
2. Go to the Profile page
3. Update your password

### Adding More Users

1. Log in as admin
2. Use the registration page to create new user accounts

## Production Considerations

For a production environment, you should:

1. Change all default passwords
2. Set `debug=False` in `main.py`
3. Use a proper web server like Gunicorn instead of Flask's development server
4. Consider moving to a more robust database system
5. Implement HTTPS by configuring SSL/TLS
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash
from app import db
from models import User, Log
from datetime import datetime
import os
from forms import LoginForm, RegistrationForm

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            
            # Update last login timestamp
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            # Log successful login
            log = Log(
                source="auth",
                log_type="login",
                message=f"User {user.username} logged in successfully",
                user_id=user.id,
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string,
                severity="info"
            )
            db.session.add(log)
            db.session.commit()
            
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            # Log failed login attempt
            log = Log(
                source="auth",
                log_type="login_failed",
                message=f"Failed login attempt for username: {form.username.data}",
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string,
                severity="warning"
            )
            db.session.add(log)
            db.session.commit()
            
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html', form=form, title='Login')

@auth_bp.route('/logout')
def logout():
    if current_user.is_authenticated:
        # Log logout
        log = Log(
            source="auth",
            log_type="logout",
            message=f"User {current_user.username} logged out",
            user_id=current_user.id,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            severity="info"
        )
        db.session.add(log)
        db.session.commit()
    
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        # Check if user already exists
        existing_user = User.query.filter_by(username=form.username.data).first()
        existing_email = User.query.filter_by(email=form.email.data).first()
        
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
        elif existing_email:
            flash('Email already registered. Please use a different email address.', 'danger')
        else:
            # Create new user
            user = User(
                username=form.username.data,
                email=form.email.data,
                first_name=form.first_name.data,
                last_name=form.last_name.data,
                role='analyst'  # Default role
            )
            user.set_password(form.password.data)
            
            db.session.add(user)
            db.session.commit()
            
            # Log user registration
            log = Log(
                source="auth",
                log_type="registration",
                message=f"New user registered: {user.username}",
                user_id=user.id,
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string,
                severity="info"
            )
            db.session.add(log)
            db.session.commit()
            
            flash('Your account has been created! You can now log in.', 'success')
            return redirect(url_for('auth.login'))
    
    return render_template('register.html', form=form, title='Register')

# Form classes
class LoginForm:
    def __init__(self):
        self.username = type('', (), {'data': None})()
        self.password = type('', (), {'data': None})()
        self.remember = type('', (), {'data': None})()
    
    def validate_on_submit(self):
        if request.method == 'POST':
            self.username.data = request.form.get('username')
            self.password.data = request.form.get('password')
            self.remember.data = 'remember' in request.form
            return all([self.username.data, self.password.data])
        return False

class RegistrationForm:
    def __init__(self):
        self.username = type('', (), {'data': None})()
        self.email = type('', (), {'data': None})()
        self.password = type('', (), {'data': None})()
        self.confirm_password = type('', (), {'data': None})()
        self.first_name = type('', (), {'data': None})()
        self.last_name = type('', (), {'data': None})()
    
    def validate_on_submit(self):
        if request.method == 'POST':
            self.username.data = request.form.get('username')
            self.email.data = request.form.get('email')
            self.password.data = request.form.get('password')
            self.confirm_password.data = request.form.get('confirm_password')
            self.first_name.data = request.form.get('first_name')
            self.last_name.data = request.form.get('last_name')
            
            # Basic validation
            if not all([self.username.data, self.email.data, self.password.data, self.confirm_password.data]):
                flash('All fields are required', 'danger')
                return False
            
            if self.password.data != self.confirm_password.data:
                flash('Passwords do not match', 'danger')
                return False
                
            if len(self.password.data) < 8:
                flash('Password must be at least 8 characters long', 'danger')
                return False
                
            return True
        return False

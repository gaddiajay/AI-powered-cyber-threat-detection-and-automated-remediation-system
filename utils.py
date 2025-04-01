import re
import ipaddress
import hashlib
import datetime
import logging
import random
import string
from flask import flash, request
from functools import wraps

# Configure logging
logger = logging.getLogger(__name__)

def validate_ip(ip_str):
    """
    Validate if a string is a valid IP address
    
    Args:
        ip_str (str): The IP address to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def sanitize_input(text):
    """
    Sanitize user input to prevent XSS and other injection attacks
    
    Args:
        text (str): The input text to sanitize
        
    Returns:
        str: The sanitized text
    """
    if not text:
        return ""
    
    # Remove HTML/script tags
    text = re.sub(r'<[^>]*>', '', text)
    
    # Remove potential script events
    text = re.sub(r'on\w+\s*=', '', text)
    
    # Remove JavaScript URLs
    text = re.sub(r'javascript:', '', text, flags=re.IGNORECASE)
    
    # Remove other potentially dangerous content
    text = re.sub(r'eval\(', '', text, flags=re.IGNORECASE)
    text = re.sub(r'expression\(', '', text, flags=re.IGNORECASE)
    
    return text

def generate_file_hash(file_data):
    """
    Generate SHA-256 hash for file data
    
    Args:
        file_data (bytes): The file data to hash
        
    Returns:
        str: The hexadecimal hash string
    """
    return hashlib.sha256(file_data).hexdigest()

def format_datetime(dt):
    """
    Format a datetime object to a readable string
    
    Args:
        dt (datetime): The datetime to format
        
    Returns:
        str: Formatted datetime string
    """
    if not dt:
        return ""
    
    now = datetime.datetime.utcnow()
    diff = now - dt
    
    if diff.days == 0:
        if diff.seconds < 60:
            return "Just now"
        elif diff.seconds < 3600:
            minutes = diff.seconds // 60
            return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
        else:
            hours = diff.seconds // 3600
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
    elif diff.days == 1:
        return "Yesterday"
    elif diff.days < 7:
        return f"{diff.days} days ago"
    else:
        return dt.strftime("%Y-%m-%d %H:%M")

def generate_random_string(length=10):
    """
    Generate a random string of letters and digits
    
    Args:
        length (int): The length of the string
        
    Returns:
        str: Random string
    """
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def get_client_ip():
    """
    Get the client's IP address from the request
    
    Returns:
        str: The client IP address
    """
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    else:
        return request.remote_addr

def flash_errors(form):
    """
    Flash all errors from a form
    
    Args:
        form: The form with errors
    """
    for field, errors in form.errors.items():
        for error in errors:
            flash(f"{getattr(form, field).label.text}: {error}", "danger")

def log_activity(db, Log, user_id, action, details, severity="info"):
    """
    Log user activity to the database
    
    Args:
        db: Database session
        Log: Log model
        user_id: ID of the user performing the action
        action: The action being logged
        details: Additional details about the action
        severity: Log severity level
    """
    try:
        log = Log(
            source="user_activity",
            log_type=action,
            message=details,
            user_id=user_id,
            ip_address=get_client_ip(),
            user_agent=request.user_agent.string,
            severity=severity
        )
        
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        logger.error(f"Failed to log activity: {str(e)}")
        db.session.rollback()

def severity_to_bootstrap_class(severity):
    """
    Convert severity level to Bootstrap color class
    
    Args:
        severity (str): The severity level
        
    Returns:
        str: Bootstrap color class
    """
    mapping = {
        'critical': 'danger',
        'high': 'danger',
        'medium': 'warning',
        'low': 'info',
        'info': 'info'
    }
    
    return mapping.get(severity.lower(), 'secondary')

def truncate_string(s, max_length=50):
    """
    Truncate a string to specified length and add ellipsis
    
    Args:
        s (str): The string to truncate
        max_length (int): Maximum length
        
    Returns:
        str: Truncated string
    """
    if not s:
        return ""
    
    if len(s) <= max_length:
        return s
    
    return s[:max_length - 3] + "..."

def admin_required(f):
    """
    Decorator for routes that require admin privileges
    
    Args:
        f: The function to decorate
        
    Returns:
        function: Decorated function
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not request.user.is_authenticated or request.user.role != 'admin':
            flash("You do not have permission to access this page.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from models import User

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    first_name = StringField('First Name', validators=[DataRequired(), Length(max=50)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', 
                                    validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already taken. Please choose a different one.')
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered. Please use a different email address.')

class NetworkScanForm(FlaskForm):
    scan_type = SelectField('Scan Type', 
                          choices=[('quick', 'Quick Scan'), 
                                  ('deep', 'Deep Scan'), 
                                  ('comprehensive', 'Comprehensive Scan')],
                          validators=[DataRequired()])
    target_ip = StringField('Target IP/Network (leave empty for all)')
    submit = SubmitField('Start Scan')

class LogAnalysisForm(FlaskForm):
    log_source = SelectField('Log Source', 
                           choices=[('all', 'All Sources'), 
                                   ('authentication', 'Authentication Logs'), 
                                   ('network', 'Network Logs'),
                                   ('system', 'System Logs'),
                                   ('application', 'Application Logs')],
                           validators=[DataRequired()])
    time_range = SelectField('Time Range', 
                           choices=[('1h', 'Last Hour'), 
                                   ('24h', 'Last 24 Hours'), 
                                   ('7d', 'Last 7 Days'),
                                   ('30d', 'Last 30 Days')],
                           validators=[DataRequired()])
    submit = SubmitField('Analyze Logs')

class RemediationForm(FlaskForm):
    action_type = SelectField('Remediation Action', 
                            choices=[('block_ip', 'Block IP Address'), 
                                    ('quarantine_file', 'Quarantine File'), 
                                    ('terminate_process', 'Terminate Process'),
                                    ('update_firewall', 'Update Firewall Rules'),
                                    ('patch_vulnerability', 'Apply Security Patch'),
                                    ('reset_credentials', 'Reset Credentials'),
                                    ('custom_action', 'Custom Remediation Script')],
                            validators=[DataRequired()])
    is_automated = BooleanField('Automated Execution')
    details = TextAreaField('Additional Details')
    submit = SubmitField('Apply Remediation')

class SecurityRuleForm(FlaskForm):
    name = StringField('Rule Name', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description')
    pattern = TextAreaField('Detection Pattern', validators=[DataRequired()])
    severity = SelectField('Severity', 
                         choices=[('low', 'Low'), 
                                 ('medium', 'Medium'), 
                                 ('high', 'High'),
                                 ('critical', 'Critical')],
                         validators=[DataRequired()])
    submit = SubmitField('Create Rule')

class SettingsForm(FlaskForm):
    scan_frequency = SelectField('Automatic Scan Frequency', 
                               choices=[('disabled', 'Disabled'), 
                                       ('hourly', 'Hourly'), 
                                       ('daily', 'Daily'),
                                       ('weekly', 'Weekly')],
                               validators=[DataRequired()])
    notification_email = StringField('Notification Email', validators=[Email()])
    threat_sensitivity = SelectField('Threat Detection Sensitivity', 
                                   choices=[('low', 'Low'), 
                                           ('medium', 'Medium'), 
                                           ('high', 'High')],
                                   validators=[DataRequired()])
    auto_remediation = BooleanField('Enable Automatic Remediation')
    submit = SubmitField('Save Settings')

class ProfileForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(max=50)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    current_password = PasswordField('Current Password')
    new_password = PasswordField('New Password', validators=[Length(min=8)])
    confirm_password = PasswordField('Confirm New Password', 
                                    validators=[EqualTo('new_password')])
    submit = SubmitField('Update Profile')

from flask import Blueprint, render_template, jsonify, request, flash, redirect, url_for
from flask_login import login_required, current_user
from app import db
from models import Threat, RemediationAction, Log
from datetime import datetime
import json
import random
import logging
import time

remediation_bp = Blueprint('remediation', __name__)
logger = logging.getLogger(__name__)

@remediation_bp.route('/remediation')
@login_required
def remediation_dashboard():
    """Main remediation dashboard view"""
    # Get active threats
    active_threats = Threat.query.filter(Threat.status.in_(['active', 'investigating'])).all()
    
    # Get recent remediation actions
    recent_actions = RemediationAction.query.order_by(RemediationAction.date_performed.desc()).limit(10).all()
    
    # Get remediation statistics
    stats = {
        'total_remediation_actions': RemediationAction.query.count(),
        'automated_actions': RemediationAction.query.filter_by(is_automated=True).count(),
        'manual_actions': RemediationAction.query.filter_by(is_automated=False).count(),
        'pending_actions': RemediationAction.query.filter_by(status='pending').count(),
        'successful_actions': RemediationAction.query.filter_by(status='completed').count(),
        'failed_actions': RemediationAction.query.filter_by(status='failed').count()
    }
    
    return render_template('remediation.html', 
                          active_threats=active_threats,
                          recent_actions=recent_actions,
                          stats=stats,
                          title='Remediation Dashboard')

@remediation_bp.route('/api/remediate/threat/<int:threat_id>', methods=['POST'])
@login_required
def remediate_threat(threat_id):
    """Apply remediation action to a specific threat"""
    try:
        threat = Threat.query.get_or_404(threat_id)
        
        # Get action details from form
        action_type = request.form.get('action_type')
        is_automated = request.form.get('is_automated', 'false').lower() == 'true'
        details = request.form.get('details', '{}')
        
        # Validate action type
        if not action_type or action_type not in ['block_ip', 'quarantine_file', 'terminate_process', 
                                                'update_firewall', 'patch_vulnerability', 'reset_credentials',
                                                'custom_action']:
            return jsonify({
                'success': False,
                'message': 'Invalid remediation action type'
            }), 400
        
        # Parse details JSON
        try:
            details_dict = json.loads(details)
        except json.JSONDecodeError:
            details_dict = {}
        
        # Create remediation action
        remediation = RemediationAction(
            action_type=action_type,
            description=generate_remediation_description(action_type, threat),
            status='pending',
            is_automated=is_automated,
            threat_id=threat.id,
            user_id=current_user.id
        )
        
        # Set action details
        remediation.set_details(details_dict)
        
        db.session.add(remediation)
        db.session.commit()
        
        # Log the remediation action creation
        log = Log(
            source="remediation",
            log_type="remediation_initiated",
            message=f"{action_type} remediation initiated for threat ID {threat_id}",
            user_id=current_user.id,
            severity="info"
        )
        db.session.add(log)
        db.session.commit()
        
        # If automated, execute the remediation now
        if is_automated:
            execute_remediation(remediation.id)
        
        return jsonify({
            'success': True,
            'message': f'Remediation action ({action_type}) initiated successfully',
            'remediation_id': remediation.id
        })
    
    except Exception as e:
        logger.error(f"Error initiating remediation: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Error initiating remediation: {str(e)}'
        }), 500

@remediation_bp.route('/api/remediation/<int:remediation_id>/execute', methods=['POST'])
@login_required
def manual_execute_remediation(remediation_id):
    """Manually execute a pending remediation action"""
    try:
        remediation = RemediationAction.query.get_or_404(remediation_id)
        
        # Check if action is already completed or failed
        if remediation.status in ['completed', 'failed']:
            return jsonify({
                'success': False,
                'message': f'Cannot execute remediation that is already in {remediation.status} state'
            }), 400
        
        # Execute the remediation
        result = execute_remediation(remediation_id)
        
        return jsonify({
            'success': True,
            'message': f'Remediation executed with result: {result}',
            'new_status': remediation.status
        })
    
    except Exception as e:
        logger.error(f"Error executing remediation: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Error executing remediation: {str(e)}'
        }), 500

@remediation_bp.route('/api/remediation/<int:remediation_id>/cancel', methods=['POST'])
@login_required
def cancel_remediation(remediation_id):
    """Cancel a pending remediation action"""
    try:
        remediation = RemediationAction.query.get_or_404(remediation_id)
        
        # Check if action can be cancelled
        if remediation.status != 'pending':
            return jsonify({
                'success': False,
                'message': f'Cannot cancel remediation that is in {remediation.status} state'
            }), 400
        
        # Cancel the remediation
        remediation.status = 'cancelled'
        remediation.result = 'Action cancelled by user'
        db.session.commit()
        
        # Log the cancellation
        log = Log(
            source="remediation",
            log_type="remediation_cancelled",
            message=f"Remediation ID {remediation_id} cancelled by user",
            user_id=current_user.id,
            severity="info"
        )
        db.session.add(log)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Remediation action cancelled successfully'
        })
    
    except Exception as e:
        logger.error(f"Error cancelling remediation: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Error cancelling remediation: {str(e)}'
        }), 500

@remediation_bp.route('/remediation/history')
@login_required
def remediation_history():
    """View remediation action history"""
    page = request.args.get('page', 1, type=int)
    actions = RemediationAction.query.order_by(RemediationAction.date_performed.desc())\
        .paginate(page=page, per_page=15)
    
    return render_template('remediation_history.html', 
                          actions=actions, 
                          title='Remediation History')

# Helper functions
def execute_remediation(remediation_id):
    """Execute a remediation action"""
    # In a real system, this would perform actual remediation
    # For this demo, we'll simulate the remediation process
    
    try:
        remediation = RemediationAction.query.get(remediation_id)
        if not remediation:
            return "Remediation action not found"
        
        # Get the associated threat
        threat = Threat.query.get(remediation.threat_id)
        if not threat:
            remediation.status = 'failed'
            remediation.result = 'Associated threat not found'
            db.session.commit()
            return 'Failed: Associated threat not found'
        
        # Simulate processing time for remediation
        time.sleep(1)
        
        # Success probability based on action type (some actions are more likely to succeed)
        success_probability = {
            'block_ip': 0.95,
            'quarantine_file': 0.9,
            'terminate_process': 0.85,
            'update_firewall': 0.8,
            'patch_vulnerability': 0.7,
            'reset_credentials': 0.9,
            'custom_action': 0.6
        }.get(remediation.action_type, 0.75)
        
        # Determine if the action succeeds
        success = random.random() < success_probability
        
        if success:
            # Action succeeded
            remediation.status = 'completed'
            remediation.result = generate_success_result(remediation.action_type, threat)
            
            # Update threat status if appropriate
            if remediation.action_type in ['block_ip', 'quarantine_file', 'patch_vulnerability']:
                threat.status = 'remediated'
                threat.date_updated = datetime.utcnow()
        else:
            # Action failed
            remediation.status = 'failed'
            remediation.result = generate_failure_result(remediation.action_type)
        
        db.session.commit()
        
        # Log the remediation execution
        log = Log(
            source="remediation",
            log_type="remediation_executed",
            message=f"Remediation ID {remediation_id} executed with status: {remediation.status}",
            user_id=remediation.user_id,
            severity="info" if success else "warning"
        )
        db.session.add(log)
        db.session.commit()
        
        return remediation.result
    
    except Exception as e:
        logger.error(f"Error in execute_remediation: {str(e)}")
        return f"Error executing remediation: {str(e)}"

def generate_remediation_description(action_type, threat):
    """Generate a description for a remediation action"""
    if action_type == 'block_ip':
        return f"Block malicious IP address {threat.source_ip} to prevent further communication"
    elif action_type == 'quarantine_file':
        return f"Quarantine suspected malicious files associated with {threat.name}"
    elif action_type == 'terminate_process':
        return f"Terminate suspicious processes related to {threat.name}"
    elif action_type == 'update_firewall':
        return f"Update firewall rules to block traffic pattern associated with {threat.name}"
    elif action_type == 'patch_vulnerability':
        return f"Apply security patch to address vulnerability exploited by {threat.name}"
    elif action_type == 'reset_credentials':
        return f"Reset compromised credentials associated with {threat.name}"
    elif action_type == 'custom_action':
        return f"Execute custom remediation script for {threat.name}"
    else:
        return f"Apply remediation action for {threat.name}"

def generate_success_result(action_type, threat):
    """Generate a success result message for a remediation action"""
    if action_type == 'block_ip':
        return f"Successfully blocked IP address {threat.source_ip} in firewall and network devices"
    elif action_type == 'quarantine_file':
        return f"Successfully quarantined {random.randint(1, 5)} suspicious files related to the threat"
    elif action_type == 'terminate_process':
        return f"Successfully terminated {random.randint(1, 3)} malicious processes"
    elif action_type == 'update_firewall':
        return f"Firewall rules updated successfully. Added {random.randint(1, 3)} new rules to block attack vector"
    elif action_type == 'patch_vulnerability':
        return f"Security patch applied successfully. System now protected against {threat.name}"
    elif action_type == 'reset_credentials':
        return f"Credentials reset successfully for {random.randint(1, 3)} potentially compromised accounts"
    elif action_type == 'custom_action':
        return f"Custom remediation script executed successfully with exit code 0"
    else:
        return "Remediation action completed successfully"

def generate_failure_result(action_type):
    """Generate a failure result message for a remediation action"""
    if action_type == 'block_ip':
        return "Failed to update one or more network devices with blocking rule. Manual intervention required."
    elif action_type == 'quarantine_file':
        return "Unable to quarantine all suspicious files. Some files may be in use or protected by the system."
    elif action_type == 'terminate_process':
        return "Failed to terminate all malicious processes. Some processes have elevated privileges."
    elif action_type == 'update_firewall':
        return "Firewall rule update failed. Possible permission issue or configuration conflict."
    elif action_type == 'patch_vulnerability':
        return "Patch application failed. System may require restart or dependencies are missing."
    elif action_type == 'reset_credentials':
        return "Credential reset partially failed. Some accounts could not be updated due to policy restrictions."
    elif action_type == 'custom_action':
        return f"Custom script execution failed with error code {random.randint(1, 127)}"
    else:
        return "Remediation action failed. Manual intervention required."

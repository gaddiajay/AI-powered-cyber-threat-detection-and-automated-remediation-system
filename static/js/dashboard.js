// Dashboard functionality for Cyber Threat Detection System
document.addEventListener('DOMContentLoaded', function() {

    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl)
    });

    // Initialize popovers
    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'))
    var popoverList = popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl)
    });

    // Initialize scan form submission
    const networkScanForm = document.getElementById('networkScanForm');
    if (networkScanForm) {
        networkScanForm.addEventListener('submit', function(event) {
            event.preventDefault();
            performNetworkScan();
        });
    }

    // Initialize log analysis form submission
    const logAnalysisForm = document.getElementById('logAnalysisForm');
    if (logAnalysisForm) {
        logAnalysisForm.addEventListener('submit', function(event) {
            event.preventDefault();
            performLogAnalysis();
        });
    }

    // Event listeners for threat status updates
    const threatStatusButtons = document.querySelectorAll('.threat-status-btn');
    threatStatusButtons.forEach(button => {
        button.addEventListener('click', function() {
            const threatId = this.getAttribute('data-threat-id');
            const newStatus = this.getAttribute('data-status');
            updateThreatStatus(threatId, newStatus);
        });
    });

    // Event listeners for remediation action triggers
    const remediationButtons = document.querySelectorAll('.remediation-action-btn');
    remediationButtons.forEach(button => {
        button.addEventListener('click', function() {
            const threatId = this.getAttribute('data-threat-id');
            const actionType = this.getAttribute('data-action-type');
            initiateRemediation(threatId, actionType);
        });
    });

    // Load charts if container exists
    if (document.getElementById('threatSeverityChart')) {
        loadDashboardCharts();
    }

    // Real-time updates for dashboard (simulated)
    if (document.getElementById('dashboard-metrics')) {
        // Update metrics every 30 seconds
        setInterval(updateMetrics, 30000);
    }
});

// Perform network scan
function performNetworkScan() {
    const scanForm = document.getElementById('networkScanForm');
    const scanType = scanForm.elements['scan_type'].value;
    const targetIp = scanForm.elements['target_ip'].value;
    const scanButton = scanForm.querySelector('button[type="submit"]');
    const scanResults = document.getElementById('scanResults');
    
    // Update UI to show scanning in progress
    scanButton.disabled = true;
    scanButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Scanning...';
    
    // Display scanning message
    scanResults.innerHTML = '<div class="alert alert-info">Network scan in progress...</div>';
    
    // Prepare form data
    const formData = new FormData();
    formData.append('scan_type', scanType);
    formData.append('target_ip', targetIp);
    
    // Send scan request to the server
    fetch('/api/scan/network', {
        method: 'POST',
        body: formData,
        credentials: 'same-origin'
    })
    .then(response => response.json())
    .then(data => {
        // Update UI with scan results
        scanButton.disabled = false;
        scanButton.innerHTML = 'Start Scan';
        
        if (data.success) {
            let alertClass = 'alert-success';
            if (data.threats_count > 0) {
                alertClass = 'alert-warning';
            }
            
            let threatsList = '';
            if (data.threats && data.threats.length > 0) {
                threatsList = '<ul class="list-group mt-3">';
                data.threats.forEach(threat => {
                    let severityClass = getSeverityClass(threat.severity);
                    threatsList += `<li class="list-group-item d-flex justify-content-between align-items-center">
                        ${threat.name}
                        <span class="badge ${severityClass} rounded-pill">${threat.severity}</span>
                    </li>`;
                });
                threatsList += '</ul>';
            }
            
            scanResults.innerHTML = `
                <div class="alert ${alertClass}">
                    ${data.message}
                </div>
                ${threatsList}
                <div class="text-end mt-3">
                    <a href="/threats" class="btn btn-primary btn-sm">View All Threats</a>
                </div>
            `;
            
            // Reload charts if they exist
            if (document.getElementById('threatSeverityChart')) {
                loadDashboardCharts();
            }
            
        } else {
            scanResults.innerHTML = `<div class="alert alert-danger">${data.message}</div>`;
        }
    })
    .catch(error => {
        console.error('Error:', error);
        scanButton.disabled = false;
        scanButton.innerHTML = 'Start Scan';
        scanResults.innerHTML = `<div class="alert alert-danger">Error performing scan: ${error.message}</div>`;
    });
}

// Perform log analysis
function performLogAnalysis() {
    const logForm = document.getElementById('logAnalysisForm');
    const logSource = logForm.elements['log_source'].value;
    const timeRange = logForm.elements['time_range'].value;
    const analyzeButton = logForm.querySelector('button[type="submit"]');
    const analysisResults = document.getElementById('analysisResults');
    
    // Update UI to show analysis in progress
    analyzeButton.disabled = true;
    analyzeButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Analyzing...';
    
    // Display analysis message
    analysisResults.innerHTML = '<div class="alert alert-info">Log analysis in progress...</div>';
    
    // Prepare form data
    const formData = new FormData();
    formData.append('log_source', logSource);
    formData.append('time_range', timeRange);
    
    // Send analysis request to the server
    fetch('/api/scan/log-analysis', {
        method: 'POST',
        body: formData,
        credentials: 'same-origin'
    })
    .then(response => response.json())
    .then(data => {
        // Update UI with analysis results
        analyzeButton.disabled = false;
        analyzeButton.innerHTML = 'Analyze Logs';
        
        if (data.success) {
            let alertClass = 'alert-success';
            if (data.threats_count > 0) {
                alertClass = 'alert-warning';
            }
            
            let threatsList = '';
            if (data.threats && data.threats.length > 0) {
                threatsList = '<ul class="list-group mt-3">';
                data.threats.forEach(threat => {
                    let severityClass = getSeverityClass(threat.severity);
                    threatsList += `<li class="list-group-item d-flex justify-content-between align-items-center">
                        ${threat.name}
                        <span class="badge ${severityClass} rounded-pill">${threat.severity}</span>
                    </li>`;
                });
                threatsList += '</ul>';
            }
            
            analysisResults.innerHTML = `
                <div class="alert ${alertClass}">
                    ${data.message}
                </div>
                ${threatsList}
                <div class="text-end mt-3">
                    <a href="/threats" class="btn btn-primary btn-sm">View All Threats</a>
                </div>
            `;
            
            // Reload charts if they exist
            if (document.getElementById('threatSeverityChart')) {
                loadDashboardCharts();
            }
            
        } else {
            analysisResults.innerHTML = `<div class="alert alert-danger">${data.message}</div>`;
        }
    })
    .catch(error => {
        console.error('Error:', error);
        analyzeButton.disabled = false;
        analyzeButton.innerHTML = 'Analyze Logs';
        analysisResults.innerHTML = `<div class="alert alert-danger">Error analyzing logs: ${error.message}</div>`;
    });
}

// Update threat status
function updateThreatStatus(threatId, newStatus) {
    // Confirm status change
    if (!confirm(`Are you sure you want to update this threat's status to ${newStatus}?`)) {
        return;
    }
    
    // Prepare form data
    const formData = new FormData();
    formData.append('status', newStatus);
    
    // Send status update request
    fetch(`/api/threat/${threatId}/update-status`, {
        method: 'POST',
        body: formData,
        credentials: 'same-origin'
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Show success message
            showToast('Success', data.message, 'success');
            
            // Update UI to reflect the new status
            const statusBadge = document.querySelector(`#threat-${threatId} .status-badge`);
            if (statusBadge) {
                statusBadge.textContent = newStatus;
                statusBadge.className = `status-badge badge ${getStatusClass(newStatus)}`;
            }
            
            // If we're on the threat details page, update the status display
            const statusDisplay = document.getElementById('threatStatusDisplay');
            if (statusDisplay) {
                statusDisplay.textContent = newStatus;
                statusDisplay.className = `badge ${getStatusClass(newStatus)} fs-6`;
            }
            
            // Reload the page after a short delay if on threats list
            if (window.location.pathname === '/threats') {
                setTimeout(() => {
                    window.location.reload();
                }, 1000);
            }
        } else {
            showToast('Error', data.message, 'danger');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showToast('Error', `Failed to update threat status: ${error.message}`, 'danger');
    });
}

// Initiate remediation for a threat
function initiateRemediation(threatId, actionType) {
    // Open modal for remediation options if it exists
    const remediationModal = document.getElementById('remediationModal');
    if (remediationModal) {
        const modal = new bootstrap.Modal(remediationModal);
        const actionTypeSelect = document.getElementById('actionTypeSelect');
        const threatIdInput = document.getElementById('threatIdInput');
        
        if (actionTypeSelect && threatIdInput) {
            actionTypeSelect.value = actionType || 'block_ip';
            threatIdInput.value = threatId;
            modal.show();
        }
    } else {
        // Direct remediation without modal
        applyRemediation(threatId, actionType, true);
    }
}

// Apply remediation action
function applyRemediation(threatId, actionType, isAutomated = false, details = {}) {
    // Prepare form data
    const formData = new FormData();
    formData.append('action_type', actionType);
    formData.append('is_automated', isAutomated);
    formData.append('details', JSON.stringify(details));
    
    // Show loading indicator
    const loadingDiv = document.getElementById('remediationLoading');
    if (loadingDiv) {
        loadingDiv.classList.remove('d-none');
    }
    
    // Send remediation request
    fetch(`/api/remediate/threat/${threatId}`, {
        method: 'POST',
        body: formData,
        credentials: 'same-origin'
    })
    .then(response => response.json())
    .then(data => {
        // Hide loading indicator
        if (loadingDiv) {
            loadingDiv.classList.add('d-none');
        }
        
        if (data.success) {
            showToast('Success', data.message, 'success');
            
            // Close modal if it exists
            const remediationModal = document.getElementById('remediationModal');
            if (remediationModal) {
                const modal = bootstrap.Modal.getInstance(remediationModal);
                if (modal) {
                    modal.hide();
                }
            }
            
            // Reload page after a short delay
            setTimeout(() => {
                window.location.reload();
            }, 1500);
        } else {
            showToast('Error', data.message, 'danger');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        if (loadingDiv) {
            loadingDiv.classList.add('d-none');
        }
        showToast('Error', `Failed to apply remediation: ${error.message}`, 'danger');
    });
}

// Submit remediation form
function submitRemediationForm() {
    const form = document.getElementById('remediationForm');
    if (!form) return;
    
    const threatId = form.elements['threat_id'].value;
    const actionType = form.elements['action_type'].value;
    const isAutomated = form.elements['is_automated'].checked;
    const details = form.elements['details'].value;
    
    let detailsObj = {};
    try {
        if (details) {
            detailsObj = JSON.parse(details);
        }
    } catch (e) {
        detailsObj = { notes: details };
    }
    
    applyRemediation(threatId, actionType, isAutomated, detailsObj);
    return false; // Prevent form submission
}

// Execute remediation action
function executeRemediationAction(remediationId) {
    if (!confirm('Are you sure you want to execute this remediation action?')) {
        return;
    }
    
    // Prepare form data
    const formData = new FormData();
    
    // Send execution request
    fetch(`/api/remediation/${remediationId}/execute`, {
        method: 'POST',
        body: formData,
        credentials: 'same-origin'
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showToast('Success', data.message, 'success');
            
            // Update status display
            const statusBadge = document.querySelector(`#remediation-${remediationId} .status-badge`);
            if (statusBadge) {
                statusBadge.textContent = data.new_status;
                statusBadge.className = `status-badge badge ${getStatusClass(data.new_status)}`;
            }
            
            // Reload page after a short delay
            setTimeout(() => {
                window.location.reload();
            }, 1500);
        } else {
            showToast('Error', data.message, 'danger');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showToast('Error', `Failed to execute remediation: ${error.message}`, 'danger');
    });
}

// Cancel remediation action
function cancelRemediationAction(remediationId) {
    if (!confirm('Are you sure you want to cancel this remediation action?')) {
        return;
    }
    
    // Prepare form data
    const formData = new FormData();
    
    // Send cancellation request
    fetch(`/api/remediation/${remediationId}/cancel`, {
        method: 'POST',
        body: formData,
        credentials: 'same-origin'
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showToast('Success', data.message, 'success');
            
            // Reload page after a short delay
            setTimeout(() => {
                window.location.reload();
            }, 1000);
        } else {
            showToast('Error', data.message, 'danger');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showToast('Error', `Failed to cancel remediation: ${error.message}`, 'danger');
    });
}

// Show toast notification
function showToast(title, message, type = 'info') {
    const toastContainer = document.getElementById('toastContainer');
    if (!toastContainer) {
        console.error('Toast container not found');
        return;
    }
    
    const id = 'toast-' + Date.now();
    
    const toastHtml = `
        <div id="${id}" class="toast" role="alert" aria-live="assertive" aria-atomic="true">
            <div class="toast-header bg-${type} text-white">
                <strong class="me-auto">${title}</strong>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="toast" aria-label="Close"></button>
            </div>
            <div class="toast-body">
                ${message}
            </div>
        </div>
    `;
    
    toastContainer.insertAdjacentHTML('beforeend', toastHtml);
    
    const toastElement = document.getElementById(id);
    const toast = new bootstrap.Toast(toastElement, { delay: 5000 });
    toast.show();
    
    // Remove toast after it's hidden
    toastElement.addEventListener('hidden.bs.toast', function() {
        toastElement.remove();
    });
}

// Update metrics on dashboard (simulated)
function updateMetrics() {
    if (!document.getElementById('dashboard-metrics')) return;
    
    // In a real implementation, this would fetch updated metrics from the server
    // For the demo, we'll just refresh the page to get the latest data
    // This would be replaced with an API call in production
    if (Math.random() > 0.7) {  // Only refresh occasionally for the demo
        window.location.reload();
    }
}

// Helper functions for UI
function getSeverityClass(severity) {
    switch (severity.toLowerCase()) {
        case 'critical':
            return 'bg-danger';
        case 'high':
            return 'bg-warning text-dark';
        case 'medium':
            return 'bg-info text-dark';
        case 'low':
            return 'bg-success';
        default:
            return 'bg-secondary';
    }
}

function getStatusClass(status) {
    switch (status.toLowerCase()) {
        case 'active':
            return 'bg-danger';
        case 'investigating':
            return 'bg-warning text-dark';
        case 'remediated':
            return 'bg-success';
        case 'false_positive':
            return 'bg-info text-dark';
        case 'completed':
            return 'bg-success';
        case 'pending':
            return 'bg-warning text-dark';
        case 'failed':
            return 'bg-danger';
        case 'cancelled':
            return 'bg-secondary';
        default:
            return 'bg-secondary';
    }
}

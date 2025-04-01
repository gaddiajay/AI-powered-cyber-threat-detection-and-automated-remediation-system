// Charts initialization for the Cyber Threat Detection Dashboard
document.addEventListener('DOMContentLoaded', function() {
    // Load charts if the dashboard page is displayed
    if (document.getElementById('threatSeverityChart') ||
        document.getElementById('threatStatusChart') ||
        document.getElementById('threatTypeChart') ||
        document.getElementById('threatTimelineChart')) {
        loadDashboardCharts();
    }
});

// Load all dashboard charts
function loadDashboardCharts() {
    // Fetch data from the API
    fetch('/api/threats/summary')
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                console.error('Error loading chart data:', data.error);
                return;
            }
            
            // Initialize charts with the received data
            initThreatSeverityChart(data.by_severity);
            initThreatStatusChart(data.by_status);
            initThreatTypeChart(data.by_type);
            initThreatTimelineChart();
        })
        .catch(error => {
            console.error('Error fetching chart data:', error);
        });
}

// Initialize Threat Severity Pie Chart
function initThreatSeverityChart(severityData) {
    const ctx = document.getElementById('threatSeverityChart');
    if (!ctx) return;
    
    // Clear any existing chart
    if (ctx.chart) {
        ctx.chart.destroy();
    }
    
    // Prepare data
    const labels = Object.keys(severityData);
    const data = Object.values(severityData);
    
    // Create color mapping
    const colorMapping = {
        'critical': '#dc3545', // danger
        'high': '#ffc107',    // warning
        'medium': '#0dcaf0',  // info
        'low': '#198754'      // success
    };
    
    // Generate colors array based on labels
    const colors = labels.map(label => colorMapping[label] || '#6c757d');
    
    // Create the chart
    ctx.chart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: labels.map(l => l.charAt(0).toUpperCase() + l.slice(1)),
            datasets: [{
                data: data,
                backgroundColor: colors,
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: '#fff'
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.raw || 0;
                            const total = context.chart.data.datasets[0].data.reduce((a, b) => a + b, 0);
                            const percentage = Math.round((value / total) * 100);
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

// Initialize Threat Status Chart
function initThreatStatusChart(statusData) {
    const ctx = document.getElementById('threatStatusChart');
    if (!ctx) return;
    
    // Clear any existing chart
    if (ctx.chart) {
        ctx.chart.destroy();
    }
    
    // Prepare data
    const labels = Object.keys(statusData);
    const data = Object.values(statusData);
    
    // Create color mapping
    const colorMapping = {
        'active': '#dc3545',       // danger
        'investigating': '#ffc107', // warning
        'remediated': '#198754',    // success
        'false_positive': '#0dcaf0' // info
    };
    
    // Generate colors array based on labels
    const colors = labels.map(label => colorMapping[label] || '#6c757d');
    
    // Create the chart
    ctx.chart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels.map(l => l.charAt(0).toUpperCase() + l.slice(1)),
            datasets: [{
                data: data,
                backgroundColor: colors,
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: '#fff'
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.raw || 0;
                            const total = context.chart.data.datasets[0].data.reduce((a, b) => a + b, 0);
                            const percentage = Math.round((value / total) * 100);
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

// Initialize Threat Type Bar Chart
function initThreatTypeChart(typeData) {
    const ctx = document.getElementById('threatTypeChart');
    if (!ctx) return;
    
    // Clear any existing chart
    if (ctx.chart) {
        ctx.chart.destroy();
    }
    
    // Prepare data
    const labels = Object.keys(typeData);
    const data = Object.values(typeData);
    
    // Format labels for better display
    const formattedLabels = labels.map(label => {
        // Convert snake_case to Title Case
        return label.split('_')
            .map(word => word.charAt(0).toUpperCase() + word.slice(1))
            .join(' ');
    });
    
    // Create the chart
    ctx.chart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: formattedLabels,
            datasets: [{
                label: 'Threats by Type',
                data: data,
                backgroundColor: 'rgba(13, 110, 253, 0.7)', // primary color
                borderColor: 'rgba(13, 110, 253, 1)',
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        color: '#fff'
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                },
                x: {
                    ticks: {
                        color: '#fff'
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                }
            }
        }
    });
}

// Initialize Threat Timeline Line Chart (simulated data for demo)
function initThreatTimelineChart() {
    const ctx = document.getElementById('threatTimelineChart');
    if (!ctx) return;
    
    // Clear any existing chart
    if (ctx.chart) {
        ctx.chart.destroy();
    }
    
    // Generate dates for the last 7 days
    const dates = [];
    const now = new Date();
    for (let i = 6; i >= 0; i--) {
        const date = new Date();
        date.setDate(now.getDate() - i);
        dates.push(date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
    }
    
    // Simulated data for demonstration - in a real app, this would come from the API
    // In a production environment, this would use actual historical data
    const critical = [0, 1, 0, 2, 1, 0, 1];
    const high = [2, 3, 1, 4, 3, 2, 3];
    const medium = [5, 4, 6, 3, 5, 4, 3];
    const low = [7, 5, 8, 6, 7, 5, 4];
    
    // Create the chart
    ctx.chart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: dates,
            datasets: [
                {
                    label: 'Critical',
                    data: critical,
                    borderColor: '#dc3545',
                    backgroundColor: 'rgba(220, 53, 69, 0.5)',
                    tension: 0.1,
                    fill: true
                },
                {
                    label: 'High',
                    data: high,
                    borderColor: '#ffc107',
                    backgroundColor: 'rgba(255, 193, 7, 0.5)',
                    tension: 0.1,
                    fill: true
                },
                {
                    label: 'Medium',
                    data: medium,
                    borderColor: '#0dcaf0',
                    backgroundColor: 'rgba(13, 202, 240, 0.5)',
                    tension: 0.1,
                    fill: true
                },
                {
                    label: 'Low',
                    data: low,
                    borderColor: '#198754',
                    backgroundColor: 'rgba(25, 135, 84, 0.5)',
                    tension: 0.1,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    stacked: true,
                    ticks: {
                        color: '#fff'
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                },
                x: {
                    ticks: {
                        color: '#fff'
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                }
            },
            plugins: {
                legend: {
                    position: 'top',
                    labels: {
                        color: '#fff'
                    }
                }
            }
        }
    });
}

// Initialize Remediation Actions Chart
function initRemediationChart(remediationData) {
    const ctx = document.getElementById('remediationChart');
    if (!ctx) return;
    
    // Clear any existing chart
    if (ctx.chart) {
        ctx.chart.destroy();
    }
    
    // If no data provided, use simulated data for demo
    if (!remediationData) {
        remediationData = {
            'block_ip': 12,
            'quarantine_file': 8,
            'terminate_process': 5,
            'update_firewall': 7,
            'patch_vulnerability': 3,
            'reset_credentials': 6,
            'custom_action': 2
        };
    }
    
    // Prepare data
    const labels = Object.keys(remediationData);
    const data = Object.values(remediationData);
    
    // Format labels for better display
    const formattedLabels = labels.map(label => {
        // Convert snake_case to Title Case
        return label.split('_')
            .map(word => word.charAt(0).toUpperCase() + word.slice(1))
            .join(' ');
    });
    
    // Create the chart
    ctx.chart = new Chart(ctx, {
        type: 'polarArea',
        data: {
            labels: formattedLabels,
            datasets: [{
                data: data,
                backgroundColor: [
                    'rgba(220, 53, 69, 0.7)',   // danger
                    'rgba(255, 193, 7, 0.7)',   // warning
                    'rgba(13, 202, 240, 0.7)',  // info
                    'rgba(25, 135, 84, 0.7)',   // success
                    'rgba(13, 110, 253, 0.7)',  // primary
                    'rgba(108, 117, 125, 0.7)', // secondary
                    'rgba(111, 66, 193, 0.7)'   // purple
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                r: {
                    ticks: {
                        color: '#fff'
                    },
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    }
                }
            },
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: '#fff'
                    }
                }
            }
        }
    });
}

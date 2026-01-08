/**
 * Chart.js Integration for MCP-FOR-SOC Reports
 * v5.1 Advanced HTML Reports
 */

// Chart configurations
const chartColors = {
    primary: '#4facfe',
    success: '#28a745',
    warning: '#ffc107',
    danger: '#dc3545',
    info: '#17a2b8',
    gray: '#6c757d'
};

/**
 * Create IOC source threat score bar chart
 */
function createSourceScoreChart(canvasId, sourcesData) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    
    // Prepare data
    const labels = sourcesData.map(s => s.name);
    const scores = sourcesData.map(s => s.score);
    const colors = scores.map(score => {
        if (score > 70) return chartColors.danger;
        if (score > 40) return chartColors.warning;
        return chartColors.success;
    });
    
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Threat Score',
                data: scores,
                backgroundColor: colors,
                borderColor: colors,
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    title: {
                        display: true,
                        text: 'Threat Score'
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                },
                title: {
                    display: true,
                    text: 'Threat Score by Source (22 Sources)'
                }
            }
        }
    });
}

/**
 * Create MITRE ATT&CK heatmap
 */
function createMITREHeatmap(canvasId, mitreData) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    
    // MITRE tactics
    const tactics = [
        'Initial Access',
        'Execution',
        'Persistence',
        'Privilege Escalation',
        'Defense Evasion',
        'Credential Access',
        'Discovery',
        'Lateral Movement',
        'Collection',
        'Exfiltration',
        'Command & Control'
    ];
    
    // Prepare data matrix
    const data = tactics.map((tactic, index) => {
        const tacticData = mitreData.find(m => m.tactic === tactic) || {};
        return {
            x: index,
            y: 0,
            v: tacticData.count || 0
        };
    });
    
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: tactics,
            datasets: [{
                label: 'Techniques Detected',
                data: data.map(d => d.v),
                backgroundColor: data.map(d => {
                    if (d.v > 5) return chartColors.danger;
                    if (d.v > 2) return chartColors.warning;
                    if (d.v > 0) return chartColors.info;
                    return chartColors.gray;
                })
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Technique Count'
                    }
                }
            },
            plugins: {
                title: {
                    display: true,
                    text: 'MITRE ATT&CK Tactics Heatmap'
                },
                legend: {
                    display: false
                }
            }
        }
    });
}

/**
 * Create verdict distribution pie chart
 */
function createVerdictChart(canvasId, verdictData) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Malicious', 'Suspicious', 'Clean', 'Unknown'],
            datasets: [{
                data: [
                    verdictData.malicious || 0,
                    verdictData.suspicious || 0,
                    verdictData.clean || 0,
                    verdictData.unknown || 0
                ],
                backgroundColor: [
                    chartColors.danger,
                    chartColors.warning,
                    chartColors.success,
                    chartColors.gray
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: 'Source Verdicts Distribution'
                },
                legend: {
                    position: 'bottom'
                }
            }
        }
    });
}

/**
 * Create sandbox analysis radar chart
 */
function createSandboxRadarChart(canvasId, sandboxData) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    
    const categories = [
        'File Operations',
        'Registry',
        'Network',
        'Process',
        'API Calls'
    ];
    
    const datasets = sandboxData.map((sandbox, index) => {
        return {
            label: sandbox.name,
            data: [
                sandbox.file_ops || 0,
                sandbox.registry || 0,
                sandbox.network || 0,
                sandbox.process || 0,
                sandbox.api_calls || 0
            ],
            borderColor: Object.values(chartColors)[index],
            backgroundColor: Object.values(chartColors)[index] + '33', // Add alpha
            borderWidth: 2
        };
    });
    
    new Chart(ctx, {
        type: 'radar',
        data: {
            labels: categories,
            datasets: datasets
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                r: {
                    beginAtZero: true,
                    max: 100
                }
            },
            plugins: {
                title: {
                    display: true,
                    text: 'Sandbox Behavioral Analysis'
                }
            }
        }
    });
}

/**
 * Create timeline chart for email hops
 */
function createEmailTimelineChart(canvasId, timelineData) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    
    // Convert timeline to chart data
    const labels = timelineData.map((hop, i) => `Hop ${i + 1}`);
    const delays = timelineData.map((hop, i) => {
        if (i === 0) return 0;
        const prev = new Date(timelineData[i-1].timestamp);
        const curr = new Date(hop.timestamp);
        return (curr - prev) / 1000; // Seconds
    });
    
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Delay (seconds)',
                data: delays,
                borderColor: chartColors.primary,
                backgroundColor: chartColors.primary + '33',
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Time Delay (s)'
                    }
                }
            },
            plugins: {
                title: {
                    display: true,
                    text: 'Email Relay Timeline'
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const hop = timelineData[context.dataIndex];
                            return [
                                `Delay: ${context.parsed.y}s`,
                                `Server: ${hop.from_server}`,
                                `IP: ${hop.from_ip}`
                            ];
                        }
                    }
                }
            }
        }
    });
}

// Export for use
window.MCPCharts = {
    createSourceScoreChart,
    createMITREHeatmap,
    createVerdictChart,
    createSandboxRadarChart,
    createEmailTimelineChart
};

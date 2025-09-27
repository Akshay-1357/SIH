// WAF Dashboard Application Logic

class WAFDashboard {
    constructor() {
        this.data = {
            realtime_stats: {
                requests_processed: 1247,
                threats_detected: 89,
                detection_rate: 7.14,
                avg_response_time: 0.85,
                uptime_hours: 72,
                blocked_requests: 67,
                allowed_requests: 1158
            },
            recent_requests: [
                {
                    id: "req_001",
                    timestamp: "2025-09-26T19:30:15Z",
                    client_ip: "192.168.1.100", 
                    method: "GET",
                    url: "/index.html",
                    risk_score: 0.15,
                    risk_level: "NORMAL",
                    threats: [],
                    action: "ALLOW",
                    response_time: 0.8
                },
                {
                    id: "req_002", 
                    timestamp: "2025-09-26T19:30:45Z",
                    client_ip: "10.0.0.50",
                    method: "GET", 
                    url: "/admin/config.php?id=1' OR 1=1--",
                    risk_score: 0.92,
                    risk_level: "CRITICAL",
                    threats: ["sql_injection"],
                    action: "BLOCK",
                    response_time: 1.2
                },
                {
                    id: "req_003",
                    timestamp: "2025-09-26T19:31:12Z", 
                    client_ip: "203.0.113.45",
                    method: "GET",
                    url: "/search?q=<script>alert('xss')</script>",
                    risk_score: 0.78,
                    risk_level: "HIGH", 
                    threats: ["xss"],
                    action: "BLOCK",
                    response_time: 0.95
                },
                {
                    id: "req_004",
                    timestamp: "2025-09-26T19:31:30Z",
                    client_ip: "192.168.1.200",
                    method: "POST", 
                    url: "/api/login",
                    risk_score: 0.25,
                    risk_level: "LOW",
                    threats: [],
                    action: "ALLOW", 
                    response_time: 0.7
                },
                {
                    id: "req_005",
                    timestamp: "2025-09-26T19:32:05Z",
                    client_ip: "198.51.100.10", 
                    method: "GET",
                    url: "/file.php?path=../../../etc/passwd",
                    risk_score: 0.88,
                    risk_level: "CRITICAL",
                    threats: ["path_traversal"], 
                    action: "BLOCK",
                    response_time: 1.1
                }
            ],
            threat_breakdown: {
                sql_injection: 23,
                xss: 19, 
                path_traversal: 15,
                command_injection: 12,
                file_inclusion: 8,
                csrf: 6,
                other: 6
            },
            risk_distribution: {
                CRITICAL: 15,
                HIGH: 28, 
                MEDIUM: 31,
                LOW: 89,
                NORMAL: 1084
            },
            performance_data: [
                {"time": "19:25", "requests": 45, "threats": 3, "response_time": 0.8},
                {"time": "19:26", "requests": 52, "threats": 5, "response_time": 0.9},
                {"time": "19:27", "requests": 38, "threats": 2, "response_time": 0.7}, 
                {"time": "19:28", "requests": 61, "threats": 7, "response_time": 1.1},
                {"time": "19:29", "requests": 43, "threats": 4, "response_time": 0.85},
                {"time": "19:30", "requests": 55, "threats": 6, "response_time": 0.95}
            ],
            top_attackers: [
                {"ip": "203.0.113.45", "requests": 67, "threats": 23, "country": "Unknown"},
                {"ip": "198.51.100.10", "requests": 45, "threats": 18, "country": "Unknown"}, 
                {"ip": "192.0.2.100", "requests": 38, "threats": 15, "country": "Unknown"}
            ],
            model_info: {
                version: "WAF-BERT-v1.0",
                accuracy: 99.7,
                precision: 99.4,
                recall: 98.8,
                f1_score: 99.1,
                last_trained: "2025-09-26T15:30:00Z",
                training_samples: 50000
            }
        };

        this.charts = {};
        this.currentView = 'dashboard';
        this.isDarkMode = window.matchMedia('(prefers-color-scheme: dark)').matches;
        this.updateInterval = null;

        this.init();
    }

    init() {
        this.setupNavigation();
        this.setupThemeToggle();
        this.setupModal();
        this.setupFilters();
        this.setupSettings();
        this.setupExport();
        this.updateDashboard();
        this.initializeCharts();
        this.startRealTimeUpdates();
        this.updateLastUpdateTime();
    }

    setupNavigation() {
        const menuLinks = document.querySelectorAll('.menu-link');
        const views = document.querySelectorAll('.view');

        menuLinks.forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const viewName = link.getAttribute('data-view');
                
                // Update active menu item
                menuLinks.forEach(l => l.classList.remove('active'));
                link.classList.add('active');
                
                // Show corresponding view
                views.forEach(v => v.classList.remove('active'));
                document.getElementById(`${viewName}-view`).classList.add('active');
                
                this.currentView = viewName;
                this.onViewChange(viewName);
            });
        });
    }

    setupThemeToggle() {
        const themeToggle = document.getElementById('theme-toggle');
        const themeIcon = themeToggle.querySelector('.theme-icon');
        
        // Set initial theme
        this.updateTheme();
        
        themeToggle.addEventListener('click', () => {
            this.isDarkMode = !this.isDarkMode;
            this.updateTheme();
        });
    }

    updateTheme() {
        const html = document.documentElement;
        const themeIcon = document.querySelector('.theme-icon');
        
        if (this.isDarkMode) {
            html.setAttribute('data-color-scheme', 'dark');
            themeIcon.textContent = '☀️';
        } else {
            html.setAttribute('data-color-scheme', 'light');
            themeIcon.textContent = '🌙';
        }
        
        // Reinitialize charts with new theme
        if (Object.keys(this.charts).length > 0) {
            setTimeout(() => this.initializeCharts(), 100);
        }
    }

    setupModal() {
        const modal = document.getElementById('request-modal');
        const modalClose = modal.querySelector('.modal-close');
        
        modalClose.addEventListener('click', () => {
            modal.classList.add('hidden');
        });
        
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.classList.add('hidden');
            }
        });
    }

    setupFilters() {
        const searchInput = document.getElementById('search-input');
        const riskFilter = document.getElementById('risk-filter');
        
        if (searchInput) {
            searchInput.addEventListener('input', () => this.filterRequests());
        }
        
        if (riskFilter) {
            riskFilter.addEventListener('change', () => this.filterRequests());
        }
    }

    setupSettings() {
        // Setup threshold sliders
        const thresholds = ['critical', 'high', 'medium'];
        thresholds.forEach(type => {
            const slider = document.getElementById(`${type}-threshold`);
            if (slider) {
                const valueSpan = slider.nextElementSibling;
                slider.addEventListener('input', () => {
                    valueSpan.textContent = parseFloat(slider.value).toFixed(2);
                });
            }
        });
    }

    setupExport() {
        const exportBtn = document.getElementById('export-threats');
        if (exportBtn) {
            exportBtn.addEventListener('click', () => this.exportReport());
        }
    }

    updateDashboard() {
        // Update stats cards
        document.getElementById('total-requests').textContent = this.data.realtime_stats.requests_processed.toLocaleString();
        document.getElementById('threats-detected').textContent = this.data.realtime_stats.threats_detected.toLocaleString();
        document.getElementById('detection-rate').textContent = `${this.data.realtime_stats.detection_rate.toFixed(1)}%`;
        document.getElementById('avg-response-time').textContent = `${(this.data.realtime_stats.avg_response_time * 1000).toFixed(0)}ms`;
        
        this.updateThreatFeed();
        this.updateRequestsTable();
        this.updateTopAttackers();
        this.updateModelInfo();
    }

    updateThreatFeed() {
        const threatFeedList = document.getElementById('threat-feed-list');
        if (!threatFeedList) return;
        
        const threats = this.data.recent_requests.filter(req => req.threats.length > 0);
        
        threatFeedList.innerHTML = threats.map(threat => `
            <div class="threat-item">
                <div class="threat-info">
                    <div class="threat-title">
                        ${threat.threats.map(t => t.replace('_', ' ').toUpperCase()).join(', ')} 
                        from ${threat.client_ip}
                    </div>
                    <div class="threat-details">
                        ${threat.method} ${threat.url.length > 50 ? threat.url.substring(0, 50) + '...' : threat.url}
                    </div>
                </div>
                <div class="threat-time">
                    ${this.formatTime(threat.timestamp)}
                </div>
            </div>
        `).join('');
    }

    updateRequestsTable() {
        const tableBody = document.getElementById('requests-table-body');
        if (!tableBody) return;
        
        this.displayedRequests = [...this.data.recent_requests];
        this.filterRequests();
    }

    filterRequests() {
        const searchInput = document.getElementById('search-input');
        const riskFilter = document.getElementById('risk-filter');
        const tableBody = document.getElementById('requests-table-body');
        
        if (!tableBody || !this.displayedRequests) return;
        
        let filteredRequests = [...this.displayedRequests];
        
        // Apply search filter
        if (searchInput && searchInput.value) {
            const searchTerm = searchInput.value.toLowerCase();
            filteredRequests = filteredRequests.filter(req => 
                req.client_ip.toLowerCase().includes(searchTerm) ||
                req.url.toLowerCase().includes(searchTerm) ||
                req.method.toLowerCase().includes(searchTerm)
            );
        }
        
        // Apply risk level filter
        if (riskFilter && riskFilter.value) {
            filteredRequests = filteredRequests.filter(req => 
                req.risk_level === riskFilter.value
            );
        }
        
        tableBody.innerHTML = filteredRequests.map(req => `
            <tr>
                <td>${this.formatTime(req.timestamp)}</td>
                <td><code>${req.client_ip}</code></td>
                <td>
                    <strong>${req.method}</strong><br>
                    <small>${req.url.length > 40 ? req.url.substring(0, 40) + '...' : req.url}</small>
                </td>
                <td>${(req.risk_score * 100).toFixed(1)}%</td>
                <td><span class="risk-badge risk-badge--${req.risk_level.toLowerCase()}">${req.risk_level}</span></td>
                <td>${req.threats.map(t => t.replace('_', ' ')).join(', ') || 'None'}</td>
                <td><span class="action-badge action-badge--${req.action.toLowerCase()}">${req.action}</span></td>
                <td><button class="btn btn--sm btn--outline" onclick="dashboard.showRequestDetails('${req.id}')">View</button></td>
            </tr>
        `).join('');
    }

    showRequestDetails(requestId) {
        const request = this.data.recent_requests.find(req => req.id === requestId);
        if (!request) return;
        
        const modal = document.getElementById('request-modal');
        const modalBody = document.getElementById('modal-body');
        
        modalBody.innerHTML = `
            <div class="modal-detail">
                <span class="modal-detail-label">Request ID</span>
                <div class="modal-detail-value">${request.id}</div>
            </div>
            <div class="modal-detail">
                <span class="modal-detail-label">Timestamp</span>
                <div class="modal-detail-value">${new Date(request.timestamp).toLocaleString()}</div>
            </div>
            <div class="modal-detail">
                <span class="modal-detail-label">Client IP</span>
                <div class="modal-detail-value">${request.client_ip}</div>
            </div>
            <div class="modal-detail">
                <span class="modal-detail-label">Method</span>
                <div class="modal-detail-value">${request.method}</div>
            </div>
            <div class="modal-detail">
                <span class="modal-detail-label">URL</span>
                <div class="modal-detail-value">${request.url}</div>
            </div>
            <div class="modal-detail">
                <span class="modal-detail-label">Risk Score</span>
                <div class="modal-detail-value">${(request.risk_score * 100).toFixed(2)}%</div>
            </div>
            <div class="modal-detail">
                <span class="modal-detail-label">Risk Level</span>
                <div class="modal-detail-value">
                    <span class="risk-badge risk-badge--${request.risk_level.toLowerCase()}">${request.risk_level}</span>
                </div>
            </div>
            <div class="modal-detail">
                <span class="modal-detail-label">Threats Detected</span>
                <div class="modal-detail-value">${request.threats.length > 0 ? request.threats.map(t => t.replace('_', ' ').toUpperCase()).join(', ') : 'None'}</div>
            </div>
            <div class="modal-detail">
                <span class="modal-detail-label">Action Taken</span>
                <div class="modal-detail-value">
                    <span class="action-badge action-badge--${request.action.toLowerCase()}">${request.action}</span>
                </div>
            </div>
            <div class="modal-detail">
                <span class="modal-detail-label">Response Time</span>
                <div class="modal-detail-value">${(request.response_time * 1000).toFixed(0)}ms</div>
            </div>
        `;
        
        modal.classList.remove('hidden');
    }

    updateTopAttackers() {
        const attackersList = document.getElementById('attackers-list');
        if (!attackersList) return;
        
        attackersList.innerHTML = this.data.top_attackers.map(attacker => `
            <div class="attacker-item">
                <div>
                    <div class="attacker-ip">${attacker.ip}</div>
                    <div class="attacker-stats">
                        <span>${attacker.requests} requests</span>
                        <span>${attacker.threats} threats</span>
                    </div>
                </div>
            </div>
        `).join('');
    }

    updateModelInfo() {
        const model = this.data.model_info;
        document.getElementById('model-version').textContent = model.version;
        document.getElementById('model-accuracy').textContent = `${model.accuracy}%`;
        document.getElementById('model-precision').textContent = `${model.precision}%`;
        document.getElementById('model-recall').textContent = `${model.recall}%`;
        document.getElementById('model-f1').textContent = `${model.f1_score}%`;
        document.getElementById('model-samples').textContent = model.training_samples.toLocaleString();
    }

    initializeCharts() {
        this.createRiskDistributionChart();
        this.createPerformanceChart();
        this.createThreatBreakdownChart();
    }

    createRiskDistributionChart() {
        const ctx = document.getElementById('risk-distribution-chart');
        if (!ctx) return;

        if (this.charts.riskDistribution) {
            this.charts.riskDistribution.destroy();
        }

        const colors = ['#1FB8CD', '#FFC185', '#B4413C', '#ECEBD5', '#5D878F'];
        
        this.charts.riskDistribution = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: Object.keys(this.data.risk_distribution),
                datasets: [{
                    data: Object.values(this.data.risk_distribution),
                    backgroundColor: colors,
                    borderWidth: 2,
                    borderColor: this.isDarkMode ? '#1F2121' : '#FCFCF9'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 20,
                            color: this.isDarkMode ? '#f5f5f5' : '#13343B'
                        }
                    }
                }
            }
        });
    }

    createPerformanceChart() {
        const ctx = document.getElementById('performance-chart');
        if (!ctx) return;

        if (this.charts.performance) {
            this.charts.performance.destroy();
        }

        this.charts.performance = new Chart(ctx, {
            type: 'line',
            data: {
                labels: this.data.performance_data.map(d => d.time),
                datasets: [
                    {
                        label: 'Requests',
                        data: this.data.performance_data.map(d => d.requests),
                        borderColor: '#1FB8CD',
                        backgroundColor: 'rgba(31, 184, 205, 0.1)',
                        tension: 0.4,
                        yAxisID: 'y'
                    },
                    {
                        label: 'Threats',
                        data: this.data.performance_data.map(d => d.threats),
                        borderColor: '#B4413C',
                        backgroundColor: 'rgba(180, 65, 60, 0.1)',
                        tension: 0.4,
                        yAxisID: 'y'
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: {
                            color: this.isDarkMode ? '#f5f5f5' : '#13343B'
                        }
                    }
                },
                scales: {
                    x: {
                        ticks: {
                            color: this.isDarkMode ? '#f5f5f5' : '#13343B'
                        },
                        grid: {
                            color: this.isDarkMode ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)'
                        }
                    },
                    y: {
                        type: 'linear',
                        display: true,
                        position: 'left',
                        ticks: {
                            color: this.isDarkMode ? '#f5f5f5' : '#13343B'
                        },
                        grid: {
                            color: this.isDarkMode ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)'
                        }
                    }
                }
            }
        });
    }

    createThreatBreakdownChart() {
        const ctx = document.getElementById('threat-breakdown-chart');
        if (!ctx) return;

        if (this.charts.threatBreakdown) {
            this.charts.threatBreakdown.destroy();
        }

        const colors = ['#1FB8CD', '#FFC185', '#B4413C', '#ECEBD5', '#5D878F', '#DB4545', '#D2BA4C'];

        this.charts.threatBreakdown = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: Object.keys(this.data.threat_breakdown).map(label => 
                    label.replace('_', ' ').toUpperCase()
                ),
                datasets: [{
                    label: 'Threats',
                    data: Object.values(this.data.threat_breakdown),
                    backgroundColor: colors,
                    borderWidth: 1,
                    borderColor: this.isDarkMode ? '#1F2121' : '#FCFCF9'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    x: {
                        ticks: {
                            color: this.isDarkMode ? '#f5f5f5' : '#13343B'
                        },
                        grid: {
                            color: this.isDarkMode ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)'
                        }
                    },
                    y: {
                        ticks: {
                            color: this.isDarkMode ? '#f5f5f5' : '#13343B'
                        },
                        grid: {
                            color: this.isDarkMode ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)'
                        }
                    }
                }
            }
        });
    }

    onViewChange(viewName) {
        if (viewName === 'intelligence' && !this.charts.threatBreakdown) {
            setTimeout(() => this.createThreatBreakdownChart(), 100);
        }
    }

    startRealTimeUpdates() {
        this.updateInterval = setInterval(() => {
            this.simulateDataUpdate();
            this.updateDashboard();
            this.updateLastUpdateTime();
        }, 5000); // Update every 5 seconds
    }

    simulateDataUpdate() {
        // Simulate new data
        this.data.realtime_stats.requests_processed += Math.floor(Math.random() * 10) + 1;
        
        // Occasionally add a new threat
        if (Math.random() < 0.3) {
            this.data.realtime_stats.threats_detected += 1;
            this.showAlert('New critical threat detected from IP: 203.0.113.45');
        }
        
        // Update detection rate
        this.data.realtime_stats.detection_rate = 
            (this.data.realtime_stats.threats_detected / this.data.realtime_stats.requests_processed) * 100;
        
        // Update response time with some variation
        this.data.realtime_stats.avg_response_time += (Math.random() - 0.5) * 0.1;
        this.data.realtime_stats.avg_response_time = Math.max(0.1, this.data.realtime_stats.avg_response_time);
    }

    updateLastUpdateTime() {
        const now = new Date();
        const timeString = now.toLocaleTimeString();
        document.getElementById('last-update-time').textContent = timeString;
    }

    showAlert(message) {
        const alertNotification = document.getElementById('alert-notification');
        const alertMessage = alertNotification.querySelector('.alert-message');
        const alertClose = alertNotification.querySelector('.alert-close');
        
        alertMessage.textContent = message;
        alertNotification.classList.remove('hidden');
        
        // Auto-hide after 5 seconds
        setTimeout(() => {
            alertNotification.classList.add('hidden');
        }, 5000);
        
        // Manual close
        alertClose.onclick = () => {
            alertNotification.classList.add('hidden');
        };
    }

    exportReport() {
        const reportData = {
            timestamp: new Date().toISOString(),
            stats: this.data.realtime_stats,
            recent_threats: this.data.recent_requests.filter(req => req.threats.length > 0),
            threat_breakdown: this.data.threat_breakdown,
            model_performance: this.data.model_info
        };
        
        const dataStr = JSON.stringify(reportData, null, 2);
        const dataBlob = new Blob([dataStr], {type: 'application/json'});
        const url = URL.createObjectURL(dataBlob);
        
        const link = document.createElement('a');
        link.href = url;
        link.download = `waf-report-${new Date().toISOString().split('T')[0]}.json`;
        link.click();
        
        URL.revokeObjectURL(url);
        this.showAlert('Report exported successfully!');
    }

    formatTime(timestamp) {
        return new Date(timestamp).toLocaleTimeString();
    }

    destroy() {
        if (this.updateInterval) {
            clearInterval(this.updateInterval);
        }
        
        Object.values(this.charts).forEach(chart => {
            if (chart && chart.destroy) {
                chart.destroy();
            }
        });
    }
}

// Initialize the dashboard when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new WAFDashboard();
});

// Handle page unload
window.addEventListener('beforeunload', () => {
    if (window.dashboard) {
        window.dashboard.destroy();
    }
});
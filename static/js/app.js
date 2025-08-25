// CTI Platform JavaScript
class CTIPlatform {
    constructor() {
        this.socket = null;
        this.currentTab = 'dashboard';
        this.init();
    }

    init() {
        this.initSocket();
        this.initNavigation();
        this.initEventListeners();
        this.loadDashboardData();
    }

    initSocket() {
        // Initialize Socket.IO connection
        this.socket = io();
        
        this.socket.on('connect', () => {
            console.log('Connected to CTI Platform');
        });

        this.socket.on('scan_progress', (data) => {
            this.updateProgress(data.progress, data.status);
        });

        this.socket.on('scan_complete', (data) => {
            this.displayURLResults(data);
        });

        this.socket.on('file_scan_complete', (data) => {
            this.displayFileResults(data);
        });

        this.socket.on('usb_event', (data) => {
            this.handleUSBEvent(data);
        });

        this.socket.on('usb_scan_complete', (data) => {
            this.displayUSBResults(data);
        });
    }

    initNavigation() {
        // Desktop navigation
        const desktopNavBtns = document.querySelectorAll('.nav-btn');
        desktopNavBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                const tab = btn.dataset.tab;
                this.switchTab(tab);
                
                // Update active state
                desktopNavBtns.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
            });
        });

        // Mobile navigation
        const mobileNavBtns = document.querySelectorAll('.nav-btn-mobile');
        mobileNavBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                const tab = btn.dataset.tab;
                this.switchTab(tab);
                
                // Update active state
                mobileNavBtns.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                
                // Also update desktop nav
                desktopNavBtns.forEach(b => {
                    if (b.dataset.tab === tab) {
                        desktopNavBtns.forEach(db => db.classList.remove('active'));
                        b.classList.add('active');
                    }
                });
            });
        });
    }

    switchTab(tabName) {
        // Hide all tabs
        const tabs = document.querySelectorAll('.tab-content');
        tabs.forEach(tab => {
            tab.classList.remove('active');
        });

        // Show selected tab
        const targetTab = document.getElementById(tabName);
        if (targetTab) {
            targetTab.classList.add('active');
            this.currentTab = tabName;

            // Load tab-specific data
            this.loadTabData(tabName);
        }
    }

    initEventListeners() {
        // URL Scanner
        const urlInput = document.getElementById('url-input');
        const scanUrlBtn = document.getElementById('scan-url-btn');

        scanUrlBtn?.addEventListener('click', () => {
            const url = urlInput.value.trim();
            if (url) {
                this.scanURL(url);
            }
        });

        urlInput?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                const url = urlInput.value.trim();
                if (url) {
                    this.scanURL(url);
                }
            }
        });

        // File Scanner
        const fileUploadArea = document.getElementById('file-upload-area');
        const fileInput = document.getElementById('file-input');

        fileUploadArea?.addEventListener('click', () => {
            fileInput.click();
        });

        fileUploadArea?.addEventListener('dragover', (e) => {
            e.preventDefault();
            fileUploadArea.classList.add('dragover');
        });

        fileUploadArea?.addEventListener('dragleave', () => {
            fileUploadArea.classList.remove('dragover');
        });

        fileUploadArea?.addEventListener('drop', (e) => {
            e.preventDefault();
            fileUploadArea.classList.remove('dragover');
            
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                this.scanFile(files[0]);
            }
        });

        fileInput?.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                this.scanFile(e.target.files[0]);
            }
        });

        // USB Monitor
        const startUSBBtn = document.getElementById('start-usb-monitor');
        const stopUSBBtn = document.getElementById('stop-usb-monitor');

        startUSBBtn?.addEventListener('click', () => {
            this.startUSBMonitoring();
        });

        stopUSBBtn?.addEventListener('click', () => {
            this.stopUSBMonitoring();
        });

        // Reports
        const refreshReportsBtn = document.getElementById('refresh-reports');
        refreshReportsBtn?.addEventListener('click', () => {
            this.loadReports();
        });
    }

    async loadDashboardData() {
        try {
            const response = await fetch('/api/dashboard/stats');
            const data = await response.json();

            // Update statistics
            document.getElementById('total-scans').textContent = data.total_scans;
            document.getElementById('threats-detected').textContent = data.threats_detected;
            document.getElementById('clean-files').textContent = data.clean_files;
            document.getElementById('open-ports').textContent = data.open_ports;

            // Update recent threats
            this.displayRecentThreats(data.recent_threats);

            // Update system status
            this.updateSystemStatus(data.system_status);

        } catch (error) {
            console.error('Error loading dashboard data:', error);
        }
    }

    displayRecentThreats(threats) {
        const container = document.getElementById('recent-threats');
        
        if (!threats || threats.length === 0) {
            container.innerHTML = '<p class="text-center" style="color: #10b981;">No recent threats detected</p>';
            return;
        }

        const threatsHTML = threats.map(threat => `
            <div class="threat-item">
                <div class="threat-icon">⚠️</div>
                <div style="flex: 1;">
                    <h4 style="margin-bottom: 0.25rem; color: #ffffff;">${threat.name}</h4>
                    <p style="color: #94a3b8; font-size: 0.9rem; margin-bottom: 0;">${threat.source}</p>
                </div>
                <div style="text-align: right;">
                    <span class="report-status ${threat.severity.toLowerCase()}">${threat.severity}</span>
                    <p style="color: #64748b; font-size: 0.8rem; margin-top: 0.25rem;">${threat.time}</p>
                </div>
            </div>
        `).join('');

        container.innerHTML = threatsHTML;
    }

    updateSystemStatus(status) {
        const usbStatus = document.getElementById('usb-monitoring-status');
        if (usbStatus) {
            if (status.usb_monitoring) {
                usbStatus.textContent = 'Active';
                usbStatus.className = 'status-indicator-small active';
            } else {
                usbStatus.textContent = 'Inactive';
                usbStatus.className = 'status-indicator-small inactive';
            }
        }
    }

    async scanURL(url) {
        try {
            // Show progress
            const progressSection = document.getElementById('url-progress');
            const resultsSection = document.getElementById('url-results');
            
            progressSection.style.display = 'block';
            resultsSection.style.display = 'none';

            // Start scan
            const response = await fetch('/api/scan/url', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url: url })
            });

            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'Scan failed');
            }

        } catch (error) {
            console.error('URL scan error:', error);
            this.showError('URL scan failed: ' + error.message);
            document.getElementById('url-progress').style.display = 'none';
        }
    }

    async scanFile(file) {
        try {
            // Show progress
            const progressSection = document.getElementById('file-progress');
            const resultsSection = document.getElementById('file-results');
            
            progressSection.style.display = 'block';
            resultsSection.style.display = 'none';

            // Prepare form data
            const formData = new FormData();
            formData.append('file', file);

            // Start scan
            const response = await fetch('/api/scan/file', {
                method: 'POST',
                body: formData
            });

            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'File scan failed');
            }

        } catch (error) {
            console.error('File scan error:', error);
            this.showError('File scan failed: ' + error.message);
            document.getElementById('file-progress').style.display = 'none';
        }
    }

    async startUSBMonitoring() {
        try {
            const response = await fetch('/api/usb/start-monitor', {
                method: 'POST'
            });

            const data = await response.json();
            
            if (data.success) {
                document.getElementById('start-usb-monitor').style.display = 'none';
                document.getElementById('stop-usb-monitor').style.display = 'inline-flex';
                this.loadUSBDevices();
            }

        } catch (error) {
            console.error('USB monitoring error:', error);
            this.showError('Failed to start USB monitoring');
        }
    }

    async stopUSBMonitoring() {
        try {
            const response = await fetch('/api/usb/stop-monitor', {
                method: 'POST'
            });

            const data = await response.json();
            
            if (data.success) {
                document.getElementById('start-usb-monitor').style.display = 'inline-flex';
                document.getElementById('stop-usb-monitor').style.display = 'none';
            }

        } catch (error) {
            console.error('USB monitoring error:', error);
            this.showError('Failed to stop USB monitoring');
        }
    }

    async loadUSBDevices() {
        try {
            const response = await fetch('/api/usb/monitor');
            const data = await response.json();

            this.displayUSBDevices(data.connected_devices);
            this.displayUSBActivity(data.recent_activity);

        } catch (error) {
            console.error('Error loading USB devices:', error);
        }
    }

    displayUSBDevices(devices) {
        const container = document.getElementById('connected-devices');
        
        if (!devices || devices.length === 0) {
            container.innerHTML = '<p class="text-center">No USB devices detected</p>';
            return;
        }

        const devicesHTML = devices.map(device => `
            <div class="device-item">
                <div class="device-info">
                    <h4>${device.device_name}</h4>
                    <p>${device.id} • ${this.formatBytes(device.total_size)}</p>
                </div>
                <div class="device-actions">
                    <button class="btn btn-small btn-primary" onclick="app.scanUSBDevice('${device.id}')">
                        <span class="btn-icon">🔍</span>
                        <span>Scan</span>
                    </button>
                </div>
            </div>
        `).join('');

        container.innerHTML = devicesHTML;
    }

    displayUSBActivity(activities) {
        const container = document.getElementById('usb-activity');
        
        if (!activities || activities.length === 0) {
            container.innerHTML = '<p class="text-center">No recent USB activity</p>';
            return;
        }

        const activitiesHTML = activities.map(activity => `
            <div class="activity-item">
                <div>
                    <strong>${activity.type.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase())}</strong>
                    <p style="color: #94a3b8; font-size: 0.9rem; margin: 0;">${activity.device_id}</p>
                </div>
                <div style="text-align: right;">
                    <span style="color: #64748b; font-size: 0.8rem;">${new Date(activity.timestamp).toLocaleTimeString()}</span>
                </div>
            </div>
        `).join('');

        container.innerHTML = activitiesHTML;
    }

    async scanUSBDevice(deviceId) {
        try {
            const response = await fetch(`/api/usb/scan/${encodeURIComponent(deviceId)}`);
            const data = await response.json();
            
            if (data.status === 'USB scan started') {
                this.showSuccess('USB scan started for device: ' + deviceId);
            }

        } catch (error) {
            console.error('USB scan error:', error);
            this.showError('Failed to start USB scan');
        }
    }

    async loadReports() {
        try {
            const response = await fetch('/api/reports');
            const data = await response.json();

            this.displayReports(data);

        } catch (error) {
            console.error('Error loading reports:', error);
        }
    }

    displayReports(reports) {
        const container = document.getElementById('reports-list');
        
        if (!reports || reports.length === 0) {
            container.innerHTML = '<p class="text-center">No reports available</p>';
            return;
        }

        const reportsHTML = reports.map(report => `
            <div class="report-item">
                <div class="report-info">
                    <h4>${report.type}</h4>
                    <p>${report.target}</p>
                    <div class="report-meta">
                        <span class="report-status ${report.status}">${report.status}</span>
                        <span style="color: #64748b; font-size: 0.8rem;">
                            ${new Date(report.timestamp).toLocaleString()}
                        </span>
                        <span style="color: #94a3b8; font-size: 0.9rem;">
                            ${report.threats} threats
                        </span>
                    </div>
                </div>
                <div class="report-actions">
                    <button class="btn btn-small btn-primary" onclick="app.downloadReport('pdf', '${report.type.toLowerCase().replace(' ', '')}', '${report.id}')">
                        <span class="btn-icon">📄</span>
                        <span>PDF</span>
                    </button>
                    <button class="btn btn-small btn-secondary" onclick="app.downloadReport('json', '${report.type.toLowerCase().replace(' ', '')}', '${report.id}')">
                        <span class="btn-icon">📋</span>
                        <span>JSON</span>
                    </button>
                </div>
            </div>
        `).join('');

        container.innerHTML = reportsHTML;
    }

    async downloadReport(format, scanType, scanId) {
        try {
            const response = await fetch(`/api/report/download/${format}/${scanType}/${scanId}`);
            
            if (response.ok) {
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `${scanType}_report_${scanId}.${format}`;
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                document.body.removeChild(a);
            } else {
                throw new Error('Download failed');
            }

        } catch (error) {
            console.error('Download error:', error);
            this.showError('Failed to download report');
        }
    }

    updateProgress(progress, status) {
        const progressFill = document.getElementById('url-progress-fill') || document.getElementById('file-progress-fill');
        const progressText = document.getElementById('url-progress-text') || document.getElementById('file-progress-text');
        
        if (progressFill) {
            progressFill.style.width = progress + '%';
        }
        
        if (progressText) {
            progressText.textContent = status;
        }
    }

    displayURLResults(result) {
        const progressSection = document.getElementById('url-progress');
        const resultsSection = document.getElementById('url-results');
        
        progressSection.style.display = 'none';
        resultsSection.style.display = 'block';

        const statusClass = result.status === 'safe' ? 'safe' : 
                           result.status === 'threat' ? 'threat' : 'suspicious';
        
        const statusIcon = result.status === 'safe' ? '🛡️' : 
                          result.status === 'threat' ? '⚠️' : '⚠️';
        
        const statusText = result.status === 'safe' ? 'URL is Safe' : 
                          result.status === 'threat' ? 'Threats Detected' : 'Suspicious Activity';

        const threatsHTML = result.threats && result.threats.length > 0 ? 
            result.threats.map(threat => `
                <div class="threat-item">
                    <div class="threat-icon">⚠️</div>
                    <span>${threat}</span>
                </div>
            `).join('') : 
            '<div class="clean-item">🛡️ No threats detected</div>';

        const portsHTML = result.open_ports && result.open_ports.length > 0 ? 
            `<table class="port-table">
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Service</th>
                        <th>State</th>
                    </tr>
                </thead>
                <tbody>
                    ${result.open_ports.map(port => `
                        <tr>
                            <td>${port.port}</td>
                            <td>${port.service}</td>
                            <td>${port.state}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>` : 
            '<p>No open ports detected</p>';

        resultsSection.innerHTML = `
            <div class="result-card ${statusClass}">
                <div class="result-header">
                    <div class="result-status">
                        <div class="result-icon ${statusClass}">${statusIcon}</div>
                        <div class="result-info">
                            <h3>${statusText}</h3>
                            <p>${result.url}</p>
                        </div>
                    </div>
                    <button class="btn btn-success" onclick="app.downloadReport('pdf', 'url', '${result.scan_id}')">
                        <span class="btn-icon">📄</span>
                        <span>Download Report</span>
                    </button>
                </div>
                
                ${result.threats && result.threats.length > 0 ? `
                <div class="threat-list">
                    <h4 style="margin-bottom: 1rem; color: #ef4444;">⚠️ Detected Threats</h4>
                    ${threatsHTML}
                </div>
                ` : `
                <div class="threat-list">
                    ${threatsHTML}
                </div>
                `}
                
                <div class="details-grid">
                    <div class="detail-card">
                        <h4>🌐 Open Ports</h4>
                        ${portsHTML}
                    </div>
                    
                    <div class="detail-card">
                        <h4>🔍 Technical Details</h4>
                        <div class="detail-item">
                            <span class="detail-label">Response Time</span>
                            <span class="detail-value">${result.response_time || 0}ms</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">SSL Valid</span>
                            <span class="detail-value">${result.ssl_valid ? 'Yes' : 'No'}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Redirects</span>
                            <span class="detail-value">${result.redirects || 0}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Reputation</span>
                            <span class="detail-value">${result.reputation || 0}/100</span>
                        </div>
                    </div>
                </div>
            </div>
        `;

        resultsSection.classList.add('fade-in');
    }

    displayFileResults(result) {
        const progressSection = document.getElementById('file-progress');
        const resultsSection = document.getElementById('file-results');
        
        progressSection.style.display = 'none';
        resultsSection.style.display = 'block';

        const statusClass = result.status === 'clean' ? 'safe' : 
                           result.status === 'infected' ? 'threat' : 'suspicious';
        
        const statusIcon = result.status === 'clean' ? '🛡️' : 
                          result.status === 'infected' ? '⚠️' : '⚠️';
        
        const statusText = result.status === 'clean' ? 'File is Clean' : 
                          result.status === 'infected' ? 'Malware Detected' : 'Suspicious File';

        const threatsHTML = result.threats && result.threats.length > 0 ? 
            result.threats.map(threat => `
                <div class="threat-item">
                    <div class="threat-icon">⚠️</div>
                    <span>${threat}</span>
                </div>
            `).join('') : 
            '<div class="clean-item">🛡️ No threats detected</div>';

        resultsSection.innerHTML = `
            <div class="result-card ${statusClass}">
                <div class="result-header">
                    <div class="result-status">
                        <div class="result-icon ${statusClass}">${statusIcon}</div>
                        <div class="result-info">
                            <h3>${statusText}</h3>
                            <p>${result.filename}</p>
                        </div>
                    </div>
                    <button class="btn btn-success" onclick="app.downloadReport('pdf', 'file', '${result.scan_id}')">
                        <span class="btn-icon">📄</span>
                        <span>Download Report</span>
                    </button>
                </div>
                
                <div class="threat-list">
                    ${threatsHTML}
                </div>
                
                <div class="details-grid">
                    <div class="detail-card">
                        <h4>📁 File Information</h4>
                        <div class="detail-item">
                            <span class="detail-label">Size</span>
                            <span class="detail-value">${this.formatBytes(result.file_info?.size || 0)}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Type</span>
                            <span class="detail-value">${result.file_info?.category || 'Unknown'}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Risk Score</span>
                            <span class="detail-value">${result.risk_score || 0}/100</span>
                        </div>
                    </div>
                    
                    <div class="detail-card">
                        <h4>🔐 Hash Analysis</h4>
                        <div class="detail-item">
                            <span class="detail-label">MD5</span>
                            <span class="detail-value" style="font-family: monospace; font-size: 0.8rem;">${result.hash_analysis?.md5 || 'N/A'}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">SHA256</span>
                            <span class="detail-value" style="font-family: monospace; font-size: 0.8rem;">${result.hash_analysis?.sha256 ? result.hash_analysis.sha256.substring(0, 32) + '...' : 'N/A'}</span>
                        </div>
                    </div>
                </div>
            </div>
        `;

        resultsSection.classList.add('fade-in');
    }

    displayUSBResults(result) {
        const resultsSection = document.getElementById('usb-scan-results');
        
        resultsSection.style.display = 'block';

        const statusClass = result.status === 'clean' ? 'safe' : 
                           result.status === 'infected' ? 'threat' : 'suspicious';
        
        const statusIcon = result.status === 'clean' ? '🛡️' : 
                          result.status === 'infected' ? '⚠️' : '⚠️';
        
        const statusText = result.status === 'clean' ? 'USB Device is Clean' : 
                          result.status === 'infected' ? 'Threats Detected' : 'Suspicious Activity';

        const threatsHTML = result.threats && result.threats.length > 0 ? 
            result.threats.map(threat => `
                <div class="threat-item">
                    <div class="threat-icon">⚠️</div>
                    <span>${threat}</span>
                </div>
            `).join('') : 
            '<div class="clean-item">🛡️ No threats detected</div>';

        const infectedFilesHTML = result.infected_files && result.infected_files.length > 0 ?
            result.infected_files.map(file => `
                <div class="threat-item">
                    <div class="threat-icon">🦠</div>
                    <div>
                        <strong>${file.path}</strong>
                        <p style="color: #94a3b8; margin: 0; font-size: 0.9rem;">${file.threat}</p>
                    </div>
                </div>
            `).join('') : '';

        resultsSection.innerHTML = `
            <div class="result-card ${statusClass}">
                <div class="result-header">
                    <div class="result-status">
                        <div class="result-icon ${statusClass}">${statusIcon}</div>
                        <div class="result-info">
                            <h3>${statusText}</h3>
                            <p>${result.device_id}</p>
                        </div>
                    </div>
                    <button class="btn btn-success" onclick="app.downloadReport('pdf', 'usb', '${result.scan_id}')">
                        <span class="btn-icon">📄</span>
                        <span>Download Report</span>
                    </button>
                </div>
                
                <div class="threat-list">
                    ${threatsHTML}
                </div>
                
                ${infectedFilesHTML ? `
                <div class="threat-list">
                    <h4 style="margin-bottom: 1rem; color: #ef4444;">🦠 Infected Files</h4>
                    ${infectedFilesHTML}
                </div>
                ` : ''}
                
                <div class="details-grid">
                    <div class="detail-card">
                        <h4>📊 Scan Summary</h4>
                        <div class="detail-item">
                            <span class="detail-label">Files Scanned</span>
                            <span class="detail-value">${result.files_scanned || 0}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Infected Files</span>
                            <span class="detail-value">${result.infected_files?.length || 0}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Suspicious Files</span>
                            <span class="detail-value">${result.suspicious_files?.length || 0}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Executables</span>
                            <span class="detail-value">${result.scan_summary?.executables || 0}</span>
                        </div>
                    </div>
                </div>
            </div>
        `;

        resultsSection.classList.add('fade-in');
    }

    handleUSBEvent(eventData) {
        console.log('USB Event:', eventData);
        
        if (this.currentTab === 'usb-monitor') {
            this.loadUSBDevices();
        }

        // Show notification
        if (eventData.type === 'device_connected') {
            this.showSuccess('USB device connected: ' + eventData.device_id);
        } else if (eventData.type === 'device_disconnected') {
            this.showSuccess('USB device disconnected: ' + eventData.device_id);
        }
    }

    loadTabData(tabName) {
        switch (tabName) {
            case 'dashboard':
                this.loadDashboardData();
                break;
            case 'usb-monitor':
                this.loadUSBDevices();
                break;
            case 'reports':
                this.loadReports();
                break;
        }
    }

    formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';

        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];

        const i = Math.floor(Math.log(bytes) / Math.log(k));

        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    showError(message) {
        this.showNotification(message, 'error');
    }

    showSuccess(message) {
        this.showNotification(message, 'success');
    }

    showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 1rem 1.5rem;
            border-radius: 0.5rem;
            color: white;
            font-weight: 500;
            z-index: 10000;
            animation: slideIn 0.3s ease-out;
            max-width: 400px;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.2);
        `;

        if (type === 'error') {
            notification.style.background = 'linear-gradient(45deg, #ef4444, #dc2626)';
        } else if (type === 'success') {
            notification.style.background = 'linear-gradient(45deg, #10b981, #059669)';
        } else {
            notification.style.background = 'linear-gradient(45deg, #0ea5e9, #06b6d4)';
        }

        notification.textContent = message;

        document.body.appendChild(notification);

        // Remove after 5 seconds
        setTimeout(() => {
            notification.style.animation = 'slideOut 0.3s ease-out';
            setTimeout(() => {
                document.body.removeChild(notification);
            }, 300);
        }, 5000);
    }
}

// Initialize the application
const app = new CTIPlatform();

// Add CSS for notifications
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
`;
document.head.appendChild(style);
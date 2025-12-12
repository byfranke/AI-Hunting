/**
 * AI-Hunting Dashboard - JavaScript Application
 * Enterprise Threat Hunting Web Application
 * Author: byFranke
 */

// Application State
const AppState = {
    currentSection: 'dashboard',
    isScanning: false,
    scanId: null,
    ws: null,
    wsReconnectAttempts: 0,
    maxReconnectAttempts: 5,
    scanResults: null,
    services: [],
    lolbasData: []
};

// DOM Elements
const DOM = {
    sidebar: document.getElementById('sidebar'),
    menuToggle: document.getElementById('menuToggle'),
    pageTitle: document.getElementById('pageTitle'),
    connectionStatus: document.getElementById('connectionStatus'),
    scanIndicator: document.getElementById('scanIndicator'),
    quickScanBtn: document.getElementById('quickScanBtn'),
    progressFill: document.getElementById('progressFill'),
    progressPhase: document.getElementById('progressPhase'),
    progressPercent: document.getElementById('progressPercent'),
    scanLog: document.getElementById('scanLog'),
    toastContainer: document.getElementById('toastContainer'),
    modal: document.getElementById('modal'),
    modalTitle: document.getElementById('modalTitle'),
    modalBody: document.getElementById('modalBody'),
    modalClose: document.getElementById('modalClose'),
    modalBackdrop: document.getElementById('modalBackdrop')
};

// Statistics Elements
const Stats = {
    services: document.getElementById('statServices'),
    critical: document.getElementById('statCritical'),
    suspicious: document.getElementById('statSuspicious'),
    clean: document.getElementById('statClean')
};

// Initialize Application
document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initWebSocket();
    initEventListeners();
    checkSystemStatus();
    loadLOLBASData();
});

// Navigation
function initNavigation() {
    const navItems = document.querySelectorAll('.nav-item');

    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const section = item.dataset.section;
            navigateTo(section);
        });
    });
}

function navigateTo(section) {
    // Update active nav item
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.toggle('active', item.dataset.section === section);
    });

    // Update active section
    document.querySelectorAll('.section').forEach(sec => {
        sec.classList.remove('active');
    });

    const targetSection = document.getElementById(`section-${section}`);
    if (targetSection) {
        targetSection.classList.add('active');
    }

    // Update page title
    const titles = {
        'dashboard': 'Dashboard',
        'scanner': 'Scanner Configuration',
        'results': 'Scan Results',
        'services': 'Windows Services',
        'lolbas': 'LOLBAS Database',
        'history': 'Scan History',
        'settings': 'Settings'
    };

    DOM.pageTitle.textContent = titles[section] || 'Dashboard';
    AppState.currentSection = section;

    // Close mobile sidebar
    DOM.sidebar.classList.remove('open');
}

// WebSocket Connection
function initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;

    try {
        AppState.ws = new WebSocket(wsUrl);

        AppState.ws.onopen = () => {
            console.log('WebSocket connected');
            updateConnectionStatus(true);
            AppState.wsReconnectAttempts = 0;
        };

        AppState.ws.onclose = () => {
            console.log('WebSocket disconnected');
            updateConnectionStatus(false);
            attemptReconnect();
        };

        AppState.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
        };

        AppState.ws.onmessage = (event) => {
            handleWebSocketMessage(JSON.parse(event.data));
        };
    } catch (error) {
        console.error('Failed to create WebSocket:', error);
        updateConnectionStatus(false);
    }
}

function attemptReconnect() {
    if (AppState.wsReconnectAttempts < AppState.maxReconnectAttempts) {
        AppState.wsReconnectAttempts++;
        const delay = Math.pow(2, AppState.wsReconnectAttempts) * 1000;
        console.log(`Reconnecting in ${delay}ms... (attempt ${AppState.wsReconnectAttempts})`);
        setTimeout(initWebSocket, delay);
    }
}

function updateConnectionStatus(connected) {
    DOM.connectionStatus.classList.toggle('connected', connected);
    DOM.connectionStatus.querySelector('.status-text').textContent = connected ? 'Connected' : 'Disconnected';

    // Update settings page
    const wsStatus = document.getElementById('wsStatus');
    if (wsStatus) {
        wsStatus.textContent = connected ? 'Connected' : 'Disconnected';
        wsStatus.style.color = connected ? 'var(--color-success)' : 'var(--color-danger)';
    }
}

function handleWebSocketMessage(data) {
    console.log('WS Message:', data);

    switch (data.type) {
        case 'connected':
            addLogEntry('Connected to AI-Hunting server', 'success');
            break;

        case 'scan_started':
            AppState.isScanning = true;
            AppState.scanId = data.scan_id;
            updateScanUI(true);
            addLogEntry('Scan started: ' + data.scan_id, 'info');
            break;

        case 'scan_progress':
            updateProgress(data.progress, data.phase, data.message);
            addLogEntry(data.message, 'info');
            break;

        case 'scan_completed':
            AppState.isScanning = false;
            AppState.scanResults = data.result;
            updateScanUI(false);
            updateProgress(100, 'completed', 'Scan completed successfully');
            addLogEntry('Scan completed successfully', 'success');
            processResults(data.result);
            showToast('Scan completed successfully', 'success');
            break;

        case 'scan_error':
            AppState.isScanning = false;
            updateScanUI(false);
            addLogEntry('Scan error: ' + data.error, 'error');
            showToast('Scan failed: ' + data.error, 'error');
            break;

        case 'scan_cancelled':
            AppState.isScanning = false;
            updateScanUI(false);
            addLogEntry('Scan cancelled by user', 'warning');
            break;

        case 'pong':
            // Heartbeat response
            break;
    }
}

// Event Listeners
function initEventListeners() {
    // Menu toggle
    DOM.menuToggle.addEventListener('click', () => {
        DOM.sidebar.classList.toggle('open');
    });

    // Quick scan button
    DOM.quickScanBtn.addEventListener('click', startQuickScan);

    // Scan form
    const scanForm = document.getElementById('scanForm');
    if (scanForm) {
        scanForm.addEventListener('submit', (e) => {
            e.preventDefault();
            startScan(new FormData(scanForm));
        });
    }

    // Cancel scan button
    const cancelScanBtn = document.getElementById('cancelScanBtn');
    if (cancelScanBtn) {
        cancelScanBtn.addEventListener('click', cancelScan);
    }

    // Tab buttons
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const tab = btn.dataset.tab;
            switchTab(tab);
        });
    });

    // VT API form
    const vtApiForm = document.getElementById('vtApiForm');
    if (vtApiForm) {
        vtApiForm.addEventListener('submit', (e) => {
            e.preventDefault();
            saveVirusTotalKey();
        });
    }

    // Toggle VT key visibility
    const toggleVtKey = document.getElementById('toggleVtKey');
    if (toggleVtKey) {
        toggleVtKey.addEventListener('click', () => {
            const input = document.getElementById('vtApiKey');
            input.type = input.type === 'password' ? 'text' : 'password';
        });
    }

    // LOLBAS reload
    const reloadLolbasBtn = document.getElementById('reloadLolbasBtn');
    if (reloadLolbasBtn) {
        reloadLolbasBtn.addEventListener('click', loadLOLBASData);
    }

    // LOLBAS search
    const lolbasSearch = document.getElementById('lolbasSearch');
    if (lolbasSearch) {
        lolbasSearch.addEventListener('input', (e) => {
            filterLOLBAS(e.target.value);
        });
    }

    // Services search and filter
    const servicesSearch = document.getElementById('servicesSearch');
    if (servicesSearch) {
        servicesSearch.addEventListener('input', () => filterServices());
    }

    const servicesFilter = document.getElementById('servicesFilter');
    if (servicesFilter) {
        servicesFilter.addEventListener('change', () => filterServices());
    }

    // Modal close
    DOM.modalClose.addEventListener('click', closeModal);
    DOM.modalBackdrop.addEventListener('click', closeModal);

    // Export button
    const exportBtn = document.getElementById('exportResultsBtn');
    if (exportBtn) {
        exportBtn.addEventListener('click', exportResults);
    }
}

// Scan Functions
function startQuickScan() {
    const options = {
        check_virustotal: true,
        check_registry: true,
        check_tasks: true,
        check_events: true,
        check_drivers: true
    };

    sendScanRequest(options);
}

function startScan(formData) {
    const options = {
        check_virustotal: formData.get('check_virustotal') === 'on',
        check_registry: formData.get('check_registry') === 'on',
        check_tasks: formData.get('check_tasks') === 'on',
        check_events: formData.get('check_events') === 'on',
        check_drivers: formData.get('check_drivers') === 'on'
    };

    sendScanRequest(options);
}

function sendScanRequest(options) {
    if (AppState.isScanning) {
        showToast('A scan is already in progress', 'warning');
        return;
    }

    if (AppState.ws && AppState.ws.readyState === WebSocket.OPEN) {
        AppState.ws.send(JSON.stringify({
            type: 'start_scan',
            options: options
        }));

        // Reset UI
        clearLogEntries();
        updateProgress(0, 'initializing', 'Starting scan...');

    } else {
        showToast('Not connected to server. Please refresh the page.', 'error');
    }
}

function cancelScan() {
    if (AppState.ws && AppState.ws.readyState === WebSocket.OPEN) {
        AppState.ws.send(JSON.stringify({ type: 'cancel_scan' }));
    }
}

function updateScanUI(scanning) {
    DOM.scanIndicator.style.display = scanning ? 'flex' : 'none';
    DOM.quickScanBtn.disabled = scanning;

    const cancelBtn = document.getElementById('cancelScanBtn');
    if (cancelBtn) {
        cancelBtn.disabled = !scanning;
    }

    const submitBtn = document.querySelector('#scanForm button[type="submit"]');
    if (submitBtn) {
        submitBtn.disabled = scanning;
    }
}

function updateProgress(percent, phase, message) {
    DOM.progressFill.style.width = `${percent}%`;
    DOM.progressPercent.textContent = `${percent}%`;
    DOM.progressPhase.textContent = message || phase;
}

// Log Functions
function addLogEntry(message, type = '') {
    const entry = document.createElement('div');
    entry.className = `log-entry ${type}`;
    entry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
    DOM.scanLog.appendChild(entry);
    DOM.scanLog.scrollTop = DOM.scanLog.scrollHeight;
}

function clearLogEntries() {
    DOM.scanLog.innerHTML = '<div class="log-entry">Scan initialized...</div>';
}

// Process Results
function processResults(results) {
    if (!results) return;

    // Update statistics
    const stats = results.statistics || {};
    Stats.services.textContent = stats.total_services || 0;
    Stats.critical.textContent = stats.critical_files || 0;
    Stats.suspicious.textContent = stats.suspicious_files || 0;
    Stats.clean.textContent = stats.clean_files || 0;

    // Store services
    AppState.services = results.results?.services || [];

    // Update tables
    updateVirusTotalTable(results.results?.virustotal || []);
    updateLOLBASResultsTable(results.results?.lolbas || []);
    updateRegistryTable(results.results?.registry || []);
    updateTasksTable(results.results?.scheduled_tasks || []);
    updateEventsTable(results.results?.events || []);
    updateDriversTable(results.results?.drivers || []);
    updateServicesTable(AppState.services);
    updateDetectionsTable(results.results?.virustotal || []);

    // Update chart
    updateChart(stats);
}

function updateDetectionsTable(vtResults) {
    const tbody = document.getElementById('detectionsBody');
    if (!tbody) return;

    const threats = vtResults.filter(r => r.classification === 'CRITICAL' || r.classification === 'SUSPICIOUS');

    if (threats.length === 0) {
        tbody.innerHTML = '<tr class="empty-row"><td colspan="5">No threats detected. Your system appears clean.</td></tr>';
        return;
    }

    tbody.innerHTML = threats.map(item => `
        <tr>
            <td><span class="badge badge-${item.classification.toLowerCase()}">${item.classification}</span></td>
            <td>${item.file_name || extractFileName(item.path) || 'Unknown'}</td>
            <td class="path-value" title="${item.path || ''}">${item.path || 'N/A'}</td>
            <td>${item.malicious || 0}/${item.total_engines || 0}</td>
            <td class="hash-value" title="${item.hash}">${item.hash ? item.hash.substring(0, 16) + '...' : 'N/A'}</td>
        </tr>
    `).join('');
}

function updateVirusTotalTable(results) {
    const tbody = document.getElementById('vtResultsBody');
    if (!tbody) return;

    if (results.length === 0) {
        tbody.innerHTML = '<tr class="empty-row"><td colspan="5">No VirusTotal results available.</td></tr>';
        return;
    }

    tbody.innerHTML = results.map(item => `
        <tr>
            <td><span class="badge badge-${(item.classification || 'unknown').toLowerCase()}">${item.classification || 'UNKNOWN'}</span></td>
            <td>${item.file_name || extractFileName(item.path) || 'Unknown'}</td>
            <td>${item.malicious || 0}/${item.total_engines || 92}</td>
            <td class="hash-value" title="${item.hash}" onclick="copyToClipboard('${item.hash}')">${item.hash || 'N/A'}</td>
            <td>
                <button class="btn btn-sm btn-secondary" onclick="viewOnVT('${item.hash}')">View on VT</button>
            </td>
        </tr>
    `).join('');
}

function updateLOLBASResultsTable(results) {
    const tbody = document.getElementById('lolbasResultsBody');
    if (!tbody) return;

    if (results.length === 0) {
        tbody.innerHTML = '<tr class="empty-row"><td colspan="4">No LOLBAS matches found.</td></tr>';
        return;
    }

    tbody.innerHTML = results.map(item => `
        <tr>
            <td><strong>${item.name}</strong></td>
            <td>${item.service_name || 'N/A'}</td>
            <td>${item.description || 'N/A'}</td>
            <td class="path-value" title="${item.service_path}">${item.service_path || 'N/A'}</td>
        </tr>
    `).join('');
}

function updateRegistryTable(results) {
    const tbody = document.getElementById('registryResultsBody');
    if (!tbody) return;

    if (results.length === 0) {
        tbody.innerHTML = '<tr class="empty-row"><td colspan="3">No registry entries found.</td></tr>';
        return;
    }

    tbody.innerHTML = results.map(item => `
        <tr>
            <td class="path-value" title="${item.Path}">${item.Path}</td>
            <td>${item.Name}</td>
            <td class="path-value" title="${item.Value}">${item.Value}</td>
        </tr>
    `).join('');
}

function updateTasksTable(results) {
    const tbody = document.getElementById('tasksResultsBody');
    if (!tbody) return;

    if (results.length === 0) {
        tbody.innerHTML = '<tr class="empty-row"><td colspan="4">No scheduled tasks found.</td></tr>';
        return;
    }

    tbody.innerHTML = results.map(item => `
        <tr>
            <td>${item.TaskName}</td>
            <td>${item.TaskPath}</td>
            <td><span class="badge badge-${item.State === 'Ready' ? 'running' : 'stopped'}">${item.State}</span></td>
            <td class="path-value" title="${item.Actions}">${item.Actions || 'N/A'}</td>
        </tr>
    `).join('');
}

function updateEventsTable(results) {
    const tbody = document.getElementById('eventsResultsBody');
    if (!tbody) return;

    if (results.length === 0) {
        tbody.innerHTML = '<tr class="empty-row"><td colspan="3">No security events found.</td></tr>';
        return;
    }

    tbody.innerHTML = results.map(item => `
        <tr>
            <td>${formatDate(item.TimeCreated)}</td>
            <td>${item.Id}</td>
            <td>${item.Message ? item.Message.substring(0, 100) + '...' : 'N/A'}</td>
        </tr>
    `).join('');
}

function updateDriversTable(results) {
    const tbody = document.getElementById('driversResultsBody');
    if (!tbody) return;

    if (results.length === 0) {
        tbody.innerHTML = '<tr class="empty-row"><td colspan="4">No drivers found.</td></tr>';
        return;
    }

    tbody.innerHTML = results.map(item => `
        <tr>
            <td>${item.Name}</td>
            <td>${item.DisplayName}</td>
            <td><span class="badge badge-${item.State === 'Running' ? 'running' : 'stopped'}">${item.State}</span></td>
            <td class="path-value" title="${item.PathName}">${item.PathName || 'N/A'}</td>
        </tr>
    `).join('');
}

function updateServicesTable(services) {
    const tbody = document.getElementById('servicesBody');
    if (!tbody) return;

    if (services.length === 0) {
        tbody.innerHTML = '<tr class="empty-row"><td colspan="5">No services data available.</td></tr>';
        return;
    }

    tbody.innerHTML = services.map(item => `
        <tr>
            <td>${item.Name}</td>
            <td>${item.DisplayName}</td>
            <td><span class="badge badge-${item.State === 'Running' ? 'running' : 'stopped'}">${item.State}</span></td>
            <td>${item.StartMode}</td>
            <td class="path-value" title="${item.PathName}">${item.PathName || 'N/A'}</td>
        </tr>
    `).join('');
}

function filterServices() {
    const search = document.getElementById('servicesSearch').value.toLowerCase();
    const filter = document.getElementById('servicesFilter').value;

    let filtered = AppState.services;

    if (search) {
        filtered = filtered.filter(s =>
            s.Name.toLowerCase().includes(search) ||
            s.DisplayName.toLowerCase().includes(search)
        );
    }

    if (filter !== 'all') {
        filtered = filtered.filter(s => s.State === filter);
    }

    updateServicesTable(filtered);
}

// Tab Functions
function switchTab(tabName) {
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tabName);
    });

    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.toggle('active', content.id === `tab-${tabName}`);
    });
}

// Chart
function updateChart(stats) {
    const canvas = document.getElementById('threatChart');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    const clean = stats.clean_files || 0;
    const suspicious = stats.suspicious_files || 0;
    const critical = stats.critical_files || 0;
    const total = clean + suspicious + critical;

    if (total === 0) {
        // Draw empty state
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        ctx.fillStyle = '#6e7681';
        ctx.font = '14px Inter';
        ctx.textAlign = 'center';
        ctx.fillText('No data available', canvas.width / 2, canvas.height / 2);
        return;
    }

    // Simple donut chart
    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;
    const radius = Math.min(centerX, centerY) - 20;
    const innerRadius = radius * 0.6;

    const data = [
        { value: clean, color: '#10b981' },
        { value: suspicious, color: '#f59e0b' },
        { value: critical, color: '#ef4444' }
    ];

    ctx.clearRect(0, 0, canvas.width, canvas.height);

    let startAngle = -Math.PI / 2;

    data.forEach(segment => {
        if (segment.value > 0) {
            const sliceAngle = (segment.value / total) * 2 * Math.PI;

            ctx.beginPath();
            ctx.arc(centerX, centerY, radius, startAngle, startAngle + sliceAngle);
            ctx.arc(centerX, centerY, innerRadius, startAngle + sliceAngle, startAngle, true);
            ctx.closePath();
            ctx.fillStyle = segment.color;
            ctx.fill();

            startAngle += sliceAngle;
        }
    });

    // Center text
    ctx.fillStyle = '#e6edf3';
    ctx.font = 'bold 24px Inter';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(total.toString(), centerX, centerY - 10);
    ctx.font = '12px Inter';
    ctx.fillStyle = '#8b949e';
    ctx.fillText('Total Files', centerX, centerY + 15);
}

// LOLBAS Functions
async function loadLOLBASData() {
    try {
        const response = await fetch('/api/lolbas/status');
        const data = await response.json();

        document.getElementById('lolbasCount').textContent = data.total_entries || 0;
        document.getElementById('lolbasLastUpdate').textContent = data.last_update ?
            new Date(data.last_update).toLocaleDateString() : 'Never';

        const lolbasStatus = document.getElementById('lolbasStatus');
        if (lolbasStatus) {
            lolbasStatus.textContent = data.is_loaded ? `Loaded (${data.total_entries} entries)` : 'Not loaded';
        }

        // Load search data if we have it
        if (data.is_loaded) {
            await searchLOLBAS('');
        }

    } catch (error) {
        console.error('Failed to load LOLBAS data:', error);
        showToast('Failed to load LOLBAS database', 'error');
    }
}

async function searchLOLBAS(query) {
    try {
        const url = query ? `/api/lolbas/search?query=${encodeURIComponent(query)}` : '/api/lolbas/search?query=cmd';
        const response = await fetch(url);
        const data = await response.json();

        AppState.lolbasData = data.results || [];
        renderLOLBASGrid(AppState.lolbasData);

    } catch (error) {
        console.error('Failed to search LOLBAS:', error);
    }
}

function filterLOLBAS(query) {
    if (query.length < 2) {
        renderLOLBASGrid(AppState.lolbasData);
        return;
    }
    searchLOLBAS(query);
}

function renderLOLBASGrid(items) {
    const grid = document.getElementById('lolbasGrid');
    if (!grid) return;

    if (items.length === 0) {
        grid.innerHTML = '<p style="color: var(--color-text-muted);">No LOLBAS entries found. Try a different search term.</p>';
        return;
    }

    grid.innerHTML = items.slice(0, 50).map(item => `
        <div class="lolbas-item">
            <h4>${item.name}</h4>
            <p>${item.description ? item.description.substring(0, 100) + '...' : 'No description'}</p>
        </div>
    `).join('');
}

// API Functions
async function checkSystemStatus() {
    try {
        const response = await fetch('/api/status');
        const data = await response.json();

        document.getElementById('backendStatus').textContent = data.status === 'online' ? 'Online' : 'Offline';
        document.getElementById('appVersion').textContent = data.version || '2.0.0';

        const vtStatus = document.getElementById('vtStatus');
        if (vtStatus) {
            vtStatus.classList.toggle('configured', data.virustotal_configured);
            vtStatus.querySelector('.status-text').textContent = data.virustotal_configured ? 'Configured' : 'Not configured';
        }

    } catch (error) {
        console.error('Failed to check system status:', error);
        document.getElementById('backendStatus').textContent = 'Error';
    }
}

async function saveVirusTotalKey() {
    const apiKey = document.getElementById('vtApiKey').value;

    if (!apiKey) {
        showToast('Please enter an API key', 'warning');
        return;
    }

    try {
        const response = await fetch('/api/config/virustotal', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ api_key: apiKey })
        });

        if (response.ok) {
            showToast('VirusTotal API key saved successfully', 'success');
            checkSystemStatus();
        } else {
            showToast('Failed to save API key', 'error');
        }

    } catch (error) {
        showToast('Failed to save API key: ' + error.message, 'error');
    }
}

// Utility Functions
function extractFileName(path) {
    if (!path) return '';
    return path.split('\\').pop().split('/').pop();
}

function formatDate(dateString) {
    if (!dateString) return 'N/A';
    try {
        return new Date(dateString).toLocaleString();
    } catch {
        return dateString;
    }
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast('Copied to clipboard', 'success');
    }).catch(() => {
        showToast('Failed to copy', 'error');
    });
}

function viewOnVT(hash) {
    if (hash) {
        window.open(`https://www.virustotal.com/gui/file/${hash}`, '_blank');
    }
}

function exportResults() {
    if (!AppState.scanResults) {
        showToast('No results to export', 'warning');
        return;
    }

    const dataStr = JSON.stringify(AppState.scanResults, null, 2);
    const dataUri = 'data:application/json;charset=utf-8,' + encodeURIComponent(dataStr);

    const exportName = `ai-hunting-results-${new Date().toISOString().slice(0, 10)}.json`;

    const linkElement = document.createElement('a');
    linkElement.setAttribute('href', dataUri);
    linkElement.setAttribute('download', exportName);
    linkElement.click();

    showToast('Results exported successfully', 'success');
}

// Toast Notifications
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <span>${message}</span>
        <button onclick="this.parentElement.remove()" style="background:none;border:none;color:inherit;cursor:pointer;margin-left:auto;">&times;</button>
    `;

    DOM.toastContainer.appendChild(toast);

    setTimeout(() => {
        toast.remove();
    }, 5000);
}

// Modal Functions
function openModal(title, content) {
    DOM.modalTitle.textContent = title;
    DOM.modalBody.innerHTML = content;
    DOM.modal.classList.add('active');
}

function closeModal() {
    DOM.modal.classList.remove('active');
}

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
    // Escape to close modal
    if (e.key === 'Escape') {
        closeModal();
    }

    // Ctrl+Shift+S to start scan
    if (e.ctrlKey && e.shiftKey && e.key === 'S') {
        e.preventDefault();
        startQuickScan();
    }
});

// Heartbeat
setInterval(() => {
    if (AppState.ws && AppState.ws.readyState === WebSocket.OPEN) {
        AppState.ws.send(JSON.stringify({ type: 'ping' }));
    }
}, 30000);

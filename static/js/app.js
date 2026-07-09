// Recon NDS Single Page Application State Management

// ==========================================
// I. Application State & Configurations
// ==========================================

let devicesState = [];
let usersState = [];
let reportsState = [];
let auditState = [];
let workstationsState = [];
let workstationAlertsState = [];
let employeesState = [];
let workspacesState = [];
let activeWorkstationId = null;
let activeDetailsTab = 'processes';
let workstationsPollingInterval = null;
let activeTab = 'devices';
let deviceSortField = 'last_seen';
let deviceSortOrder = 'desc';
let isScanning = false;
let authToken = sessionStorage.getItem("authToken") || null;
let currentUsername = sessionStorage.getItem("currentUsername") || null;
let currentRole = sessionStorage.getItem("currentRole") || null;
let currentFullName = sessionStorage.getItem("currentFullName") || null;

const deviceTypeIcons = {
    'router': 'network',
    'server': 'hard-drive',
    'workstation': 'monitor',
    'mobile': 'smartphone',
    'printer': 'printer',
    'smart-tv': 'tv',
    'generic': 'help-circle'
};

const HIGH_RISK_PORTS = [21, 23, 137, 138, 139, 445, 3389];

function parseUTCDateTime(dateString) {
    if (!dateString) return null;
    let parseableString = dateString;
    if (typeof dateString === 'string') {
        if (dateString.includes(' ') && !dateString.includes('T')) {
            parseableString = dateString.replace(' ', 'T');
        }
        if (!parseableString.endsWith('Z') && !parseableString.includes('+') && !/-\d{2}:\d{2}$/.test(parseableString)) {
            parseableString += 'Z';
        }
    }
    return new Date(parseableString);
}

function formatFriendlyTime(dateInput) {
    if (!dateInput) return 'N/A';
    const date = typeof dateInput === 'string' || typeof dateInput === 'number'
        ? parseUTCDateTime(dateInput)
        : dateInput;

    if (!date || isNaN(date.getTime())) return 'N/A';

    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);

    if (diffMs < 0 && diffMs > -5000) {
        return 'Just now';
    }

    if (diffMs >= 0) {
        if (diffMs < 5000) {
            return 'Just now';
        }
        if (diffMins < 1) {
            return 'Seconds ago';
        }
        if (diffMins < 60) {
            return `${diffMins} min${diffMins > 1 ? 's' : ''} ago`;
        }
        if (diffHours < 24) {
            return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
        }
    }

    const yesterday = new Date(now);
    yesterday.setDate(now.getDate() - 1);
    if (date.toDateString() === yesterday.toDateString()) {
        const timeOptions = { hour: 'numeric', minute: '2-digit', hour12: true };
        return `Yesterday at ${date.toLocaleTimeString('en-US', timeOptions)}`;
    }

    if (date.toDateString() === now.toDateString()) {
        const timeOptions = { hour: 'numeric', minute: '2-digit', hour12: true };
        return `Today at ${date.toLocaleTimeString('en-US', timeOptions)}`;
    }

    const options = {
        month: 'short',
        day: 'numeric',
        year: 'numeric',
        hour: 'numeric',
        minute: '2-digit',
        hour12: true
    };
    return date.toLocaleDateString('en-US', options);
}

function formatAbsoluteDateTime(dateInput) {
    if (!dateInput) return 'N/A';
    const date = typeof dateInput === 'string' || typeof dateInput === 'number'
        ? parseUTCDateTime(dateInput)
        : dateInput;

    if (!date || isNaN(date.getTime())) return 'N/A';

    const pad = (num) => String(num).padStart(2, '0');
    const yyyy = date.getFullYear();
    const mm = pad(date.getMonth() + 1);
    const dd = pad(date.getDate());
    const hh = pad(date.getHours());
    const min = pad(date.getMinutes());
    const ss = pad(date.getSeconds());

    return `${yyyy}-${mm}-${dd} ${hh}:${min}:${ss}`;
}

function getAuthHeaders() {
    const headers = {
        'Content-Type': 'application/json'
    };
    if (authToken) {
        headers['Authorization'] = `Bearer ${authToken}`;
    }
    return headers;
}

// ==========================================
// II. API Services Client
// ==========================================

// Initialize when page loads
document.addEventListener("DOMContentLoaded", () => {
    initApp();
});

function initApp() {
    const loginOverlay = document.getElementById("login-overlay");
    if (!authToken) {
        if (loginOverlay) loginOverlay.classList.add("active");
        lucide.createIcons();
        return;
    }
    if (loginOverlay) loginOverlay.classList.remove("active");

    // Show logged-in user info in sidebar
    updateSidebarUserInfo();

    fetchDevices();
    fetchUsers();
    fetchReports();
    fetchAuditLogs();
    fetchWorkstations();
    fetchWorkstationAlerts();
    fetchEmployees();
    fetchWorkspaces();
    fetchDashboardStats();
    applyRoleAccessControl();
    lucide.createIcons();
    startInactivityTimer();
    
    // Initialize real-time event listener
    initSSE();

    // Load infrastructure tree and start status listener
    loadDynamicNetworkTree().then(() => {
        connectStatusWebSocket();
    });
}

function updateSidebarUserInfo() {
    const infoPanel = document.getElementById('logged-in-user-info');
    if (!infoPanel) return;
    infoPanel.style.display = 'flex';
    const displayName = currentFullName || currentUsername || 'User';
    const nameEl = document.getElementById('user-info-name');
    const roleEl = document.getElementById('user-info-role-badge');
    const avatarEl = document.getElementById('user-avatar-initials');
    if (nameEl) nameEl.textContent = displayName;
    if (roleEl) {
        const cleanRoleMap = {
            'super_admin': 'System Admin',
            'operator': 'Security Officer',
            'Staff': 'Staff Member',
            'user': 'Staff Member'
        };
        roleEl.textContent = cleanRoleMap[currentRole] || currentRole || 'Staff Member';
    }
    if (avatarEl) {
        const parts = displayName.trim().split(' ');
        avatarEl.textContent = parts.length >= 2
            ? (parts[0][0] + parts[parts.length - 1][0]).toUpperCase()
            : displayName.substring(0, 2).toUpperCase();
    }
}

function handleApiError(response) {
    if (response.status === 401) {
        logout();
        showToast("Session expired or invalid. Please sign in again.");
        return true;
    }
    if (response.status === 403) {
        showToast("Operation forbidden: Insufficient privileges.");
        return true;
    }
    return false;
}

// Fetch all devices from backend
async function fetchDevices() {
    try {
        const response = await fetch("/api/devices/?limit=1000", { headers: getAuthHeaders() });
        if (handleApiError(response)) return;
        if (!response.ok) throw new Error("Failed to fetch devices");
        devicesState = await response.json();

        updateSortIcons();
        filterDevices();
        renderTrustedSidebar(devicesState);
        updateMetrics();
    } catch (error) {
        console.error("Error fetching devices:", error);
        showToast("Error loading network devices.");
    }
}

// Fetch all registered operators
async function fetchUsers() {
    try {
        const response = await fetch("/api/users/", { headers: getAuthHeaders() });
        if (response.status === 403) {
            usersState = [];
            renderUsers(null);
            return;
        }
        if (handleApiError(response)) return;
        if (!response.ok) throw new Error("Failed to fetch users");
        usersState = await response.json();
        renderUsers(usersState);
    } catch (error) {
        console.error("Error fetching users:", error);
        showToast("Error loading operator list.");
    }
}

// Fetch scan reports history
async function fetchReports() {
    try {
        const response = await fetch("/api/reports/", { headers: getAuthHeaders() });
        if (response.status === 403) {
            reportsState = [];
            renderReports(null);
            return;
        }
        if (handleApiError(response)) return;
        if (!response.ok) throw new Error("Failed to fetch reports");
        reportsState = await response.json();
        renderReports(reportsState);
        updateLastScanMetric();
    } catch (error) {
        console.error("Error fetching reports:", error);
        showToast("Error loading scan logs.");
    }
}

// Fetch security audit logs
async function fetchAuditLogs() {
    try {
        const response = await fetch("/api/audit/", { headers: getAuthHeaders() });
        if (response.status === 403) {
            auditState = [];
            renderAuditLogs(null);
            return;
        }
        if (handleApiError(response)) return;
        if (!response.ok) throw new Error("Failed to fetch audit logs");
        auditState = await response.json();
        renderAuditLogs(auditState);
    } catch (error) {
        console.error("Error fetching audit logs:", error);
        showToast("Error loading security audit logs.");
    }
}

// ==========================================
// III. UI Renderers
// ==========================================
// Render Trusted Sidebar
function renderTrustedSidebar(devices) {
    const sidebarList = document.getElementById("trusted-devices-list");
    if (!sidebarList) return;

    // Filter only trusted devices
    const trustedDevices = devices.filter(dev => dev.trust_level === 'Trusted');

    if (trustedDevices.length === 0) {
        sidebarList.innerHTML = `<div class="trusted-device-empty">No trusted devices yet.</div>`;
        return;
    }

    sidebarList.innerHTML = trustedDevices.map(dev => {
        const typeIcon = deviceTypeIcons[dev.os_type] || 'help-circle';
        return `
            <div class="trusted-device-card">
                <div class="trusted-device-icon">
                    <i data-lucide="${typeIcon}"></i>
                </div>
                <div class="trusted-device-info">
                    <span class="trusted-device-name" title="${dev.hostname || 'Unknown Host'}">${dev.hostname || 'Unknown Host'}</span>
                    <span class="trusted-device-ip">${dev.ip}</span>
                </div>
            </div>
        `;
    }).join('');

    lucide.createIcons();
}

// Render devices in the HTML table
function renderDevices(devices) {
    const listBody = document.getElementById("devices-list-body");
    if (!listBody) return;

    // Filter device lists based on simulated Staff role
    let listToRender = devices;
    if (currentRole === 'Staff') {
        listToRender = devices.filter(dev => dev.owner_name === 'Jane Doe');
    }

    if (listToRender.length === 0) {
        listBody.innerHTML = `
            <tr>
                <td colspan="8" class="empty-state-row">
                    <i data-lucide="help-circle" class="empty-state-icon"></i>
                    <p class="empty-state-text">No devices found.</p>
                </td>
            </tr>
        `;
        lucide.createIcons();
        return;
    }

    listBody.innerHTML = listToRender.map(dev => {
        const formattedDate = formatFriendlyTime(dev.last_seen);

        // Parse open ports list
        let portsList = [];
        try {
            portsList = dev.open_ports ? JSON.parse(dev.open_ports) : [];
        } catch (e) {
            console.error("Error parsing ports for IP:", dev.ip, e);
        }

        // Get Device Type Icon
        const typeIcon = deviceTypeIcons[dev.os_type] || 'help-circle';

        // Render port pills (highlight high-risk ports in red)
        let portsHtml = '<span class="no-ports">None</span>';
        const devJsonBase64 = btoa(unescape(encodeURIComponent(JSON.stringify(dev))));

        if (portsList.length > 0) {
            const displayPorts = portsList.slice(0, 2);
            let pills = displayPorts.map(p => {
                const isHighRisk = HIGH_RISK_PORTS.includes(p.port);
                const portClass = isHighRisk ? 'port-badge-pill high-risk' : 'port-badge-pill';
                const pillTitle = isHighRisk ? `${p.service} (Exposed High-Risk Service!)` : p.service;
                return `<span class="${portClass}" title="${pillTitle}">${p.port}</span>`;
            }).join('');

            if (portsList.length > 2) {
                pills += `<span class="port-badge-more-pill" onclick="viewPorts('${devJsonBase64}')">+${portsList.length - 2}</span>`;
            }
            portsHtml = `<div class="ports-cell-wrapper">${pills}</div>`;
        } else if (dev.status === 'active' && currentRole !== 'Staff') {
            portsHtml = `<span class="scan-needed-link" onclick="runDevicePortScan(${dev.id})">Scan needed</span>`;
        }

        // Handle Hostname with Trust indicators
        let hostnameHtml = dev.hostname || 'Unknown';
        if (!dev.is_trusted && dev.trust_level === 'Unknown') {
            hostnameHtml = `<span class="host-unverified"><i data-lucide="shield-alert" class="icon-unverified"></i> ${hostnameHtml}</span>`;
        } else if (dev.trust_level === 'Blocked') {
            hostnameHtml = `<span class="host-blocked"><i data-lucide="shield-off" class="icon-blocked"></i> ${hostnameHtml}</span>`;
        } else {
            hostnameHtml = `<span class="host-trusted"><i data-lucide="shield-check" class="icon-trusted"></i> ${hostnameHtml}</span>`;
        }

        // Show owner and department info as sub-text under hostname
        let ownerDeptHtml = "";
        if (dev.owner_name && dev.owner_name !== "None") {
            ownerDeptHtml = `<div class="device-meta-assigned">Owner: ${dev.owner_name} (${dev.department || 'N/A'})</div>`;
        } else {
            ownerDeptHtml = `<div class="device-meta-unassigned">Unassigned Device</div>`;
        }

        // Trust Toggle Button Configuration
        const trustButtonText = dev.is_trusted ? 'Revoke Trust' : 'Trust Device';
        const trustButtonClass = dev.is_trusted ? 'btn-trust trusted' : 'btn-trust';

        // Map trust level badge classes
        let trustLevelHtml = "";
        if (dev.trust_level === 'Trusted') {
            trustLevelHtml = `<span class="badge badge-active"><span class="bullet-indicator"></span>Trusted</span>`;
        } else if (dev.trust_level === 'Blocked') {
            trustLevelHtml = `<span class="badge badge-blocked"><span class="bullet-indicator"></span>Blocked</span>`;
        } else if (dev.trust_level === 'Pending') {
            trustLevelHtml = `<span class="badge badge-pending"><span class="bullet-indicator"></span>Pending</span>`;
        } else {
            trustLevelHtml = `<span class="badge badge-unknown"><span class="bullet-indicator"></span>Unknown</span>`;
        }

        // Patch Status Badge
        let patchHtml = '';
        if (dev.firmware_eol) {
            patchHtml = `<span class="patch-badge patch-eol" title="End-of-Life: no patches available">&#x1F534; EOL</span>`;
        } else if (dev.firmware_version && dev.latest_firmware && dev.firmware_version !== dev.latest_firmware) {
            patchHtml = `<span class="patch-badge patch-needed" title="Installed: ${dev.firmware_version} | Latest: ${dev.latest_firmware}">&#x1F7E1; Needs Patch</span>`;
        } else if (dev.firmware_version && dev.latest_firmware && dev.firmware_version === dev.latest_firmware) {
            patchHtml = `<span class="patch-badge patch-ok" title="Up to date: ${dev.firmware_version}">&#x1F7E2; Up to Date</span>`;
        } else {
            patchHtml = `<span class="patch-badge patch-unknown" title="No version info recorded">&#x26AB; Unknown</span>`;
        }

        // RBAC Actions configuration
        let actionsCellHtml = "";
        if (currentRole === 'Staff') {
            actionsCellHtml = `<span class="read-only-label">Read-Only Mode</span>`;
        } else {
            const deleteBtnHtml = currentRole === 'super_admin'
                ? `<button class="btn-danger-text" onclick="deleteDevice(${dev.id})">Delete</button>`
                : '';

            actionsCellHtml = `
                <div class="dropdown-actions">
                    <button class="btn-dropdown-trigger" onclick="toggleActionsDropdown(this, event)" title="Device Actions">
                        <i data-lucide="more-horizontal"></i>
                    </button>
                    <div class="dropdown-menu-content">
                        <button class="${trustButtonClass}" onclick="toggleDeviceTrust(${dev.id})">${trustButtonText}</button>
                        <button class="btn-scan-ports" onclick="runDevicePortScan(${dev.id})">Scan Ports</button>
                        <button class="btn-edit-text" onclick="editDevice('${devJsonBase64}')">Edit Device</button>
                        ${deleteBtnHtml ? `<button class="dropdown-item btn-danger-text" onclick="deleteDevice(${dev.id})">Delete Device</button>` : ''}
                    </div>
                </div>
            `;
        }

        return `
            <tr class="${!dev.is_trusted ? 'untrusted-row' : ''}" data-device-ip="${dev.ip}">
                <td>
                    <div class="device-type-icon-wrapper" title="Classification: ${dev.os_type || 'generic'}">
                        <i data-lucide="${typeIcon}"></i>
                    </div>
                </td>
                <td>
                    <div>
                        ${hostnameHtml}
                        ${ownerDeptHtml}
                    </div>
                </td>
                <td>
                    <div><code class="code-ip">${dev.ip}</code></div>
                    <div><code class="code-mac" style="font-size: 11px; color: var(--color-text-muted);">${dev.mac || 'N/A'}</code></div>
                </td>
                <td>${dev.vendor || 'Unknown Brand'}</td>
                <td>
                    <div style="margin-bottom: 4px;">${trustLevelHtml}</div>
                    <div>${patchHtml}</div>
                </td>
                <td>${portsHtml}</td>
                <td class="td-last-seen">${formattedDate}</td>
                <td class="actions-col">${actionsCellHtml}</td>
            </tr>
        `;
    }).join('');

    lucide.createIcons();
}

// Render users in the HTML table
function renderUsers(users) {
    const listBody = document.getElementById("users-list-body");
    if (!listBody) return;

    if (users === null) {
        listBody.innerHTML = `<tr><td colspan="5" class="users-empty" style="color: var(--color-error); font-weight: 500; text-align: center; padding: 24px;"><i data-lucide="shield-alert" class="icon-blocked" style="vertical-align: middle; margin-right: 6px; width: 18px; height: 18px;"></i> Access Denied: Insufficient privileges.</td></tr>`;
        lucide.createIcons();
        return;
    }

    if (users.length === 0) {
        listBody.innerHTML = `<tr><td colspan="5" class="users-empty">No registered users.</td></tr>`;
        return;
    }

    const roleBadgeMap = {
        'super_admin': 'badge-active',
        'operator': 'badge-role',
        'user': 'badge-unknown',
        'administrator': 'badge-active',   // legacy compat
    };
    const roleLabelMap = {
        'super_admin': 'System Administrator',
        'operator': 'IT Security Officer',
        'user': 'Staff Member',
        'administrator': 'System Administrator',   // legacy
    };

    listBody.innerHTML = users.map(user => {
        const roleClass = roleBadgeMap[user.role] || 'badge-role';
        const roleLabel = roleLabelMap[user.role] || user.role;
        const deleteButton = currentRole === 'super_admin'
            ? `<button class="btn-danger-text" onclick="deleteUser(${user.id})">Remove</button>`
            : `<span class="users-locked">Locked</span>`;
        const resetButton = currentRole === 'super_admin'
            ? `<button class="btn-edit-text" onclick="resetUserPassword(${user.id}, '${user.username}')" style="margin-right: 8px;">Reset PW</button>`
            : '';
        const lockBadge = user.locked_until
            ? `<span class="badge badge-inactive" title="Locked until ${user.locked_until}">Locked</span>`
            : (user.is_active
                ? `<span class="badge badge-active">Active</span>`
                : `<span class="badge badge-inactive">Disabled</span>`);
        const unlockBtn = (user.locked_until && currentRole === 'super_admin')
            ? `<button class="btn-assign-device" onclick="unlockUser(${user.id})">Unlock</button>`
            : '';

        return `
            <tr>
                <td class="users-username">${user.username}</td>
                <td>${user.full_name || 'N/A'}</td>
                <td>${user.email || 'N/A'}</td>
                <td><span class="badge ${roleClass}">${roleLabel}</span></td>
                <td>
                    ${lockBadge}
                    ${unlockBtn}
                </td>
                <td class="actions-col" style="white-space: nowrap;">
                    ${resetButton}
                    ${deleteButton}
                </td>
            </tr>
        `;
    }).join('');

    lucide.createIcons();
}

// Render scan logs in the HTML table
function renderReports(reports) {
    const listBody = document.getElementById("reports-list-body");
    if (!listBody) return;

    if (reports === null) {
        listBody.innerHTML = `<tr><td colspan="6" class="reports-empty" style="color: var(--color-error); font-weight: 500; text-align: center; padding: 24px;"><i data-lucide="shield-alert" class="icon-blocked" style="vertical-align: middle; margin-right: 6px; width: 18px; height: 18px;"></i> Access Denied: Insufficient privileges.</td></tr>`;
        lucide.createIcons();
        return;
    }

    if (reports.length === 0) {
        listBody.innerHTML = `<tr><td colspan="6" class="reports-empty">No scan reports logged yet.</td></tr>`;
        return;
    }

    listBody.innerHTML = reports.map(rep => {
        const formattedDate = formatAbsoluteDateTime(rep.timestamp);
        return `
            <tr>
                <td class="reports-date">${formattedDate}</td>
                <td><code class="reports-subnet">${rep.summary ? rep.summary.split('on ')[1].split('.')[0] : '192.168.1.0/24'}</code></td>
                <td>${rep.devices_found}</td>
                <td><span class="reports-active-count">${rep.active_devices}</span></td>
                <td>${rep.scan_duration_secs}s</td>
                <td class="reports-summary">${rep.summary || 'N/A'}</td>
            </tr>
        `;
    }).join('');
}

// Render audit logs in the HTML table
function renderAuditLogs(logs) {
    const listBody = document.getElementById("audit-list-body");
    if (!listBody) return;

    if (logs === null) {
        listBody.innerHTML = `<tr><td colspan="7" class="audit-empty" style="color: var(--color-error); font-weight: 500; text-align: center; padding: 24px;"><i data-lucide="shield-alert" class="icon-blocked" style="vertical-align: middle; margin-right: 6px; width: 18px; height: 18px;"></i> Access Denied: Insufficient privileges.</td></tr>`;
        lucide.createIcons();
        return;
    }

    if (logs.length === 0) {
        listBody.innerHTML = `<tr><td colspan="7" class="audit-empty">No audit events tracked yet.</td></tr>`;
        return;
    }

    listBody.innerHTML = logs.map(log => {
        const formattedDate = formatAbsoluteDateTime(log.timestamp);
        let actionBadge = 'badge-role';
        if (log.action === 'REGISTER') actionBadge = 'badge-active';
        if (log.action === 'SCAN') actionBadge = 'badge-role';
        if (log.action === 'POLICY') actionBadge = 'badge-unknown';
        if (log.action === 'DELETE') actionBadge = 'badge-inactive';

        return `
            <tr>
                <td class="audit-timestamp">${formattedDate}</td>
                <td class="audit-username">${log.username || 'system'}</td>
                <td><span class="badge badge-role audit-role">${log.role || 'system'}</span></td>
                <td><span class="badge ${actionBadge}">${log.action}</span></td>
                <td><code class="code-ip">${log.ip_address || 'N/A'}</code></td>
                <td><code class="audit-target">${log.target || 'N/A'}</code></td>
                <td class="audit-details">${log.details || 'N/A'}</td>
            </tr>
        `;
    }).join('');
}

// Update KPI Stats elements
function updateMetrics() {
    let listToRender = devicesState;
    if (currentRole === 'Staff') {
        listToRender = devicesState.filter(dev => dev.owner_name === 'Jane Doe');
    }
    const totalCount = listToRender.length;
    const activeCount = listToRender.filter(d => d.status === 'active').length;

    document.getElementById("stat-total-devices").innerText = totalCount;
    document.getElementById("stat-active-devices").innerText = activeCount;
}

// Update last active scan timestamp
function updateLastScanMetric() {
    const lastScanVal = document.getElementById("stat-last-scan");
    if (reportsState.length > 0) {
        lastScanVal.innerText = formatFriendlyTime(reportsState[0].timestamp);
    } else {
        lastScanVal.innerText = "Never";
    }
}

// Switch tabs inside navigation menu

function toggleSubmenu(id) {
    const el = document.getElementById(id);
    const parent = el.parentElement;
    if (el.style.display === "none") {
        el.style.display = "flex";
        parent.classList.add("expanded");
    } else {
        el.style.display = "none";
        parent.classList.remove("expanded");
    }
}

function switchTab(tabId) {
    activeTab = tabId;

    if (workstationsPollingInterval) {
        clearInterval(workstationsPollingInterval);
        workstationsPollingInterval = null;
    }

    document.querySelectorAll(".nav-item").forEach(btn => btn.classList.remove("active"));
    const activeBtnMap = {
        'dashboard': 'btn-nav-dashboard',
        'devices': 'btn-nav-devices',
        'users': 'btn-nav-users',
        'reports': 'btn-nav-reports',
        'audit': 'btn-nav-audit',
        'workstations': 'btn-nav-workstations',
        'threat-alerts': 'btn-nav-threat-alerts',
        'employees': 'btn-nav-employees',
        'workspaces': 'btn-nav-workspaces'
    };
    if (activeBtnMap[tabId]) {
        document.getElementById(activeBtnMap[tabId]).classList.add("active");
    }

    document.querySelectorAll(".tab-pane").forEach(pane => pane.classList.remove("active"));
    document.getElementById(`tab-${tabId}`).classList.add("active");

    const headerTitle = document.getElementById("page-title");
    const headerSubtitle = document.getElementById("page-subtitle");
    const headerActions = document.getElementById("custom-subnet-box");
    const statsRow = document.getElementById("dashboard-stats-row");
    const btnAddDevice = document.getElementById("btn-add-device");
    const btnTriggerScan = document.getElementById("btn-trigger-scan");
    const btnClearDevices = document.getElementById("btn-clear-devices");

    if (tabId === 'dashboard') {
        headerTitle.innerText = "Overview Dashboard";
        headerSubtitle.innerText = "Security posture summary and network health analytics.";
        headerActions.style.display = "none";
        statsRow.style.display = "none";
        fetchDashboardStats();
    } else if (tabId === 'devices') {
        headerTitle.innerText = "Devices Directory";
        headerSubtitle.innerText = "Real-time listing of active and logged network nodes.";
        if (currentRole !== 'user') {
            headerActions.style.display = "flex";
            if (btnAddDevice) btnAddDevice.style.display = "inline-flex";
            if (btnTriggerScan) btnTriggerScan.style.display = "inline-flex";
            if (btnClearDevices) btnClearDevices.style.display = currentRole === 'super_admin' ? "inline-flex" : "none";
        } else {
            headerActions.style.display = "none";
        }
        statsRow.style.display = "grid";
    } else if (tabId === 'users') {
        headerTitle.innerText = "Access Controls";
        headerSubtitle.innerText = "Manage system user accounts and role assignments.";
        headerActions.style.display = "none";
        statsRow.style.display = "none";
    } else if (tabId === 'employees') {
        headerTitle.innerText = "HR Employee Directory";
        headerSubtitle.innerText = "Register and manage employee profiles and device assignments.";
        headerActions.style.display = "none";
        statsRow.style.display = "none";
        fetchEmployees();
    } else if (tabId === 'workspaces') {
        headerTitle.innerText = "Workspace Management";
        headerSubtitle.innerText = "Define and manage physical workspaces and their assigned devices.";
        headerActions.style.display = "none";
        statsRow.style.display = "none";
        fetchWorkspaces();
    } else if (tabId === 'reports') {
        headerTitle.innerText = "Subnet Scan Logs";
        headerSubtitle.innerText = "Comprehensive audit history of background network sweeps.";
        headerActions.style.display = "none";
        statsRow.style.display = "none";
    } else if (tabId === 'audit') {
        headerTitle.innerText = "Security Audit Logs";
        headerSubtitle.innerText = "Historical record of system activities, scan completions, and operator reviews.";
        headerActions.style.display = "none";
        statsRow.style.display = "none";
        fetchAuditLogs();
    } else if (tabId === 'workstations') {
        headerTitle.innerText = "Workstation Security Monitor";
        headerSubtitle.innerText = "Real-time workstation endpoint protection and telemetry logging.";
        headerActions.style.display = "none";
        statsRow.style.display = "none";
        fetchWorkstations();

        workstationsPollingInterval = setInterval(() => {
            fetchWorkstations();
        }, 4000);
    } else if (tabId === 'threat-alerts') {
        headerTitle.innerText = "Active Threat Alerts";
        headerSubtitle.innerText = "Real-time security alerts and active vulnerability notifications.";
        headerActions.style.display = "none";
        statsRow.style.display = "none";
        fetchWorkstationAlerts();

        workstationsPollingInterval = setInterval(() => {
            fetchWorkstationAlerts();
        }, 4000);
    }
}

// changeSimulationRole kept for backward compat (no-op now — replaced by real login)
function changeSimulationRole() {
    showToast('Please use the login form to authenticate with different roles.');
}

function logout() {
    authToken = null;
    currentUsername = null;
    currentRole = null;
    currentFullName = null;
    sessionStorage.clear();

    const loginOverlay = document.getElementById("login-overlay");
    if (loginOverlay) loginOverlay.classList.add("active");

    const infoPanel = document.getElementById('logged-in-user-info');
    if (infoPanel) infoPanel.style.display = 'none';

    const loginForm = document.getElementById("form-login");
    if (loginForm) loginForm.reset();

    closeModal('modal-pin-verify');
    
    if (eventSource) {
        eventSource.close();
        eventSource = null;
    }
}

async function handleLoginSubmit(event) {
    event.preventDefault();
    const usernameInput = document.getElementById("login-username").value.trim();
    const passwordInput = document.getElementById("login-password").value;

    const errorContainer = document.getElementById("login-error-container");
    if (errorContainer) errorContainer.style.display = "none";

    const btn = document.getElementById("btn-login");
    if (btn) { btn.disabled = true; btn.innerHTML = `<span>Signing In...</span>`; }

    try {
        const response = await fetch("/api/users/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username: usernameInput, password: btoa(passwordInput) })
        });

        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.detail || "Authentication failed");
        }

        const data = await response.json();

        authToken = data.access_token;
        currentUsername = data.username;
        currentRole = data.role === 'user' ? 'Staff' : data.role;
        currentFullName = data.full_name || data.username;

        sessionStorage.setItem("authToken", authToken);
        sessionStorage.setItem("currentUsername", currentUsername);
        sessionStorage.setItem("currentRole", currentRole);
        sessionStorage.setItem("currentFullName", currentFullName);

        // System administrator PIN gate
        if (data.pin_required) {
            const loginOverlay = document.getElementById("login-overlay");
            if (loginOverlay) loginOverlay.classList.remove("active");
            openModal('modal-pin-verify');
            setTimeout(() => document.getElementById('pin-d1')?.focus(), 100);
            showToast(`Password verified. Enter your System Administrator security PIN.`);
        } else {
            showToast(`Access granted. Welcome, ${currentFullName}.`);
            initApp();
        }
    } catch (error) {
        console.error("Login failed:", error);
        if (errorContainer) {
            const errorText = document.getElementById("login-error-text");
            if (errorText) {
                errorText.textContent = error.message;
                errorContainer.style.display = "flex";
                lucide.createIcons();
            }
        }
        showToast(`Login failed: ${error.message}`);
    } finally {
        if (btn) { btn.disabled = false; btn.innerHTML = `<span>Sign In to Console</span>`; }
    }
}

// ── Super Admin PIN Functions ─────────────────────────────────
function pinAutoFocus(currentInput, nextId) {
    if (currentInput.value && nextId) {
        document.getElementById(nextId)?.focus();
    }
}

function pinKeyDown(event, currentInput, prevId) {
    if (event.key === 'Backspace' && !currentInput.value && prevId) {
        document.getElementById(prevId)?.focus();
    }
    if (event.key === 'Enter') submitPin();
}

async function submitPin() {
    const digits = ['pin-d1', 'pin-d2', 'pin-d3', 'pin-d4', 'pin-d5', 'pin-d6']
        .map(id => document.getElementById(id)?.value || '');
    const pin = digits.join('');

    if (pin.length < 6) { showToast('Please enter all 6 digits.'); return; }

    // Clear PIN inputs from the DOM immediately for security
    document.querySelectorAll('.pin-digit').forEach(d => d.value = '');

    const btn = document.getElementById('btn-submit-pin');
    if (btn) btn.disabled = true;

    try {
        const response = await fetch('/api/users/verify-pin', {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({ pin: btoa(pin) })
        });

        if (!response.ok) {
            const err = await response.json();
            // Shake animation
            document.querySelectorAll('.pin-digit').forEach(d => {
                d.value = '';
                d.classList.add('pin-error');
                setTimeout(() => d.classList.remove('pin-error'), 400);
            });
            document.getElementById('pin-error-msg').style.display = 'block';
            document.getElementById('pin-d1')?.focus();
            throw new Error(err.detail || 'Invalid PIN');
        }

        const data = await response.json();
        authToken = data.access_token;
        sessionStorage.setItem('authToken', authToken);

        closeModal('modal-pin-verify');
        document.getElementById('pin-error-msg').style.display = 'none';
        showToast(`PIN verified. Welcome, ${currentFullName}.`);
        initApp();
    } catch (error) {
        showToast(`PIN verification failed: ${error.message}`);
    } finally {
        if (btn) btn.disabled = false;
    }
}

function applyRoleAccessControl() {
    const isSuperAdmin = currentRole === 'super_admin';
    const isOperator = currentRole === 'operator';
    const isUser = currentRole === 'user' || currentRole === 'Staff';

    const show = (id, visible) => {
        const el = document.getElementById(id);
        if (el) el.style.display = visible ? (el.tagName === 'BUTTON' ? 'inline-flex' : 'flex') : 'none';
    };

    // Default: everything visible
    show('btn-add-device', !isUser);
    show('btn-trigger-scan', !isUser);
    show('btn-clear-devices', isSuperAdmin);
    show('custom-subnet-box', !isUser);
    show('btn-nav-users', isSuperAdmin);
    show('btn-nav-audit', isSuperAdmin || isOperator);
    show('btn-nav-employees', isSuperAdmin || isOperator);
    show('btn-nav-workspaces', isSuperAdmin || isOperator);
    show('btn-add-employee', isSuperAdmin);
    show('btn-add-workspace', isSuperAdmin || isOperator);

    if (isUser) {
        // Staff: devices and workstations only
        if (!['devices', 'workstations'].includes(activeTab)) {
            switchTab('devices');
        }
    } else if (isOperator) {
        // Operator: no Users (Access Control) tab
        if (activeTab === 'users') switchTab('devices');
    }
}

// openModal is defined at the bottom of app.js with full modal support

function closeModal(modalId) {
    document.getElementById(modalId).classList.remove("active");
}

// Add/Update Device form submission handler
async function saveDevice(event) {
    event.preventDefault();

    const deviceId = document.getElementById("edit-device-id").value;
    const isEdit = deviceId !== "";

    const deviceData = {
        ip: document.getElementById("device-ip").value.trim(),
        mac: document.getElementById("device-mac").value.trim() || null,
        hostname: document.getElementById("device-hostname").value.trim() || null,
        vendor: document.getElementById("device-vendor").value.trim() || null,
        status: document.getElementById("device-status").value,
        os_type: document.getElementById("device-type").value,
        owner_name: document.getElementById("device-owner").value.trim() || null,
        department: document.getElementById("device-dept").value,
        purpose: document.getElementById("device-purpose").value.trim() || null,
        trust_level: document.getElementById("device-trust-level").value,
        is_trusted: document.getElementById("device-trust-level").value === "Trusted",
        // OS & Patch fields
        baseline_os: document.getElementById("device-baseline-os").value.trim() || null,
        current_os: document.getElementById("device-current-os").value.trim() || null,
        firmware_version: document.getElementById("device-firmware-version").value.trim() || null,
        latest_firmware: document.getElementById("device-latest-firmware").value.trim() || null,
        firmware_eol: document.getElementById("device-firmware-eol").value === "true"
    };

    try {
        let response;
        if (isEdit) {
            response = await fetch(`/api/devices/${deviceId}`, {
                method: "PUT",
                headers: getAuthHeaders(),
                body: JSON.stringify(deviceData)
            });
        } else {
            response = await fetch("/api/devices/", {
                method: "POST",
                headers: getAuthHeaders(),
                body: JSON.stringify(deviceData)
            });
        }

        if (handleApiError(response)) return;
        if (!response.ok) {
            const errorDetails = await response.json();
            throw new Error(errorDetails.detail || "Save operation failed.");
        }

        showToast(isEdit ? "Device updated successfully." : "New device registered.");
        closeModal("modal-device");
        fetchDevices();
        fetchAuditLogs();
    } catch (error) {
        console.error("Error saving device:", error);
        showToast(`Failed: ${error.message}`);
    }
}

// Edit button callback
function editDevice(deviceBase64) {
    const dev = JSON.parse(decodeURIComponent(escape(atob(deviceBase64))));

    document.getElementById("device-modal-title").innerText = "Edit Device Parameters";
    document.getElementById("edit-device-id").value = dev.id;
    document.getElementById("device-ip").value = dev.ip;
    document.getElementById("device-ip").disabled = true;
    document.getElementById("device-mac").value = dev.mac || "";
    document.getElementById("device-hostname").value = dev.hostname || "";
    document.getElementById("device-vendor").value = dev.vendor || "";
    document.getElementById("device-status").value = dev.status;
    document.getElementById("device-type").value = dev.os_type || "generic";
    document.getElementById("device-owner").value = dev.owner_name || "";
    document.getElementById("device-dept").value = dev.department || "None";
    document.getElementById("device-purpose").value = dev.purpose || "";
    document.getElementById("device-trust-level").value = dev.trust_level || "Unknown";
    // OS & Patch fields
    document.getElementById("device-baseline-os").value = dev.baseline_os || "";
    document.getElementById("device-current-os").value = dev.current_os || "";
    document.getElementById("device-firmware-version").value = dev.firmware_version || "";
    document.getElementById("device-latest-firmware").value = dev.latest_firmware || "";
    document.getElementById("device-firmware-eol").value = dev.firmware_eol ? "true" : "false";

    document.getElementById("modal-device").classList.add("active");
}

// Delete device callback
async function deleteDevice(deviceId) {
    if (!confirm("Are you sure you want to delete this device from Recon NDS?")) return;

    try {
        const response = await fetch(`/api/devices/${deviceId}`, {
            method: "DELETE",
            headers: getAuthHeaders()
        });
        if (handleApiError(response)) return;
        if (!response.ok) throw new Error("Delete request failed");

        showToast("Device deleted successfully.");
        fetchDevices();
        fetchAuditLogs();
    } catch (error) {
        console.error("Error deleting device:", error);
        showToast("Failed to delete device.");
    }
}

// Clear all devices from the database (Super Admin only)
async function clearAllDevices() {
    if (!confirm("WARNING: This will permanently delete ALL discovered and registered devices from the database. Are you sure you want to proceed?")) return;

    try {
        const response = await fetch("/api/devices/clear", {
            method: "POST",
            headers: getAuthHeaders()
        });
        if (handleApiError(response)) return;
        if (!response.ok) throw new Error("Clear operation failed.");

        showToast("Database cleared successfully.");
        await fetchDevices();
        fetchAuditLogs();
    } catch (error) {
        console.error("Error clearing database:", error);
        showToast(`Failed: ${error.message}`);
    }
}

// Toggle device trust status
async function toggleDeviceTrust(deviceId) {
    try {
        const response = await fetch(`/api/devices/${deviceId}/toggle-trust`, {
            method: "POST",
            headers: getAuthHeaders()
        });
        if (handleApiError(response)) return;
        if (!response.ok) throw new Error("Failed to toggle trust status.");

        const result = await response.json();
        showToast(result.is_trusted ? "Device marked as TRUSTED." : "Device flagged as UNTRUSTED/PENDING.");
        fetchDevices();
        fetchAuditLogs();
    } catch (error) {
        console.error("Error toggling device trust:", error);
        showToast("Failed to update trust status.");
    }
}

// Create new user handler
async function saveUser(event) {
    event.preventDefault();

    const userData = {
        username: document.getElementById("user-username").value.trim(),
        full_name: document.getElementById("user-fullname").value.trim() || null,
        email: document.getElementById("user-email").value.trim() || null,
        role: document.getElementById("user-role").value,
        is_active: document.getElementById("user-active").checked
    };

    try {
        const response = await fetch("/api/users/", {
            method: "POST",
            headers: getAuthHeaders(),
            body: JSON.stringify(userData)
        });

        if (handleApiError(response)) return;
        if (!response.ok) {
            const errorDetails = await response.json();
            throw new Error(errorDetails.detail || "User creation failed.");
        }

        showToast("User account registered. Default password: username + '123'");
        closeModal("modal-user");
        fetchUsers();
    } catch (error) {
        console.error("Error registering user:", error);
        showToast(`Failed: ${error.message}`);
    }
}

// Delete user callback
async function deleteUser(userId) {
    if (!confirm("Remove this operator's console access credentials?")) return;

    try {
        const response = await fetch(`/api/users/${userId}`, {
            method: "DELETE",
            headers: getAuthHeaders()
        });
        if (handleApiError(response)) return;
        if (!response.ok) throw new Error("Operator removal failed.");

        showToast("Operator removed.");
        fetchUsers();
    } catch (error) {
        console.error("Error deleting operator:", error);
        showToast("Failed to remove operator.");
    }
}

// Reset operator password callback
async function resetUserPassword(userId, username) {
    if (!confirm(`Are you sure you want to reset the password for operator '${username}' back to the default '${username}123'?`)) return;

    try {
        const response = await fetch(`/api/users/${userId}/reset-password`, {
            method: "POST",
            headers: getAuthHeaders()
        });
        if (handleApiError(response)) return;
        if (!response.ok) throw new Error("Password reset failed.");

        showToast(`Password successfully reset to default: '${username}123'`);
        fetchUsers();
    } catch (error) {
        console.error("Error resetting password:", error);
        showToast(`Failed: ${error.message}`);
    }
}

// Subnet Scanning Background Trigger & Active Polling UX
async function triggerScan() {
    if (isScanning) return;

    isScanning = true;

    document.getElementById("scanner-loader-title").innerText = "Scanning Subnet Scope";
    document.getElementById("scanner-loader-description").innerText = "Recon NDS is triggering an Nmap ping sweep across the target subnet range. Please hold on...";
    document.getElementById("scanning-loader").classList.add("active");

    const progressText = document.getElementById("scan-progress-text");
    progressText.innerText = "Dispatching Nmap ping packets...";

    const customSubnet = document.getElementById("custom-subnet-input").value.trim();
    let url = "/api/devices/scan";
    if (customSubnet) {
        url += `?subnet=${encodeURIComponent(customSubnet)}`;
    }

    const initialReportsCount = reportsState.length;

    try {
        const response = await fetch(url, {
            method: "POST",
            headers: getAuthHeaders()
        });
        if (handleApiError(response)) return;
        if (!response.ok) throw new Error("Scan activation failed.");

        setTimeout(() => {
            progressText.innerText = "Filtering active node IPs...";
        }, 1500);

        setTimeout(() => {
            progressText.innerText = "Classifying device roles and cataloging vendor details...";
        }, 3200);

        pollScanCompletion(initialReportsCount, Date.now());
    } catch (error) {
        console.error("Error starting scan:", error);
        showToast("Network scan failed to initialize.");
        isScanning = false;
        document.getElementById("scanning-loader").classList.remove("active");
    }
}

// Polling loop waiting for background scan task report log
async function pollScanCompletion(initialCount, startTime) {
    if (Date.now() - startTime > 35000) {
        finishScan(false, "Scanning timed out. Check logs.");
        return;
    }

    try {
        const response = await fetch("/api/reports/", { headers: getAuthHeaders() });
        if (response.status === 401 || response.status === 403) {
            handleApiError(response);
            finishScan(false, "Scanning aborted due to authentication failure.");
            return;
        }
        if (response.ok) {
            const currentReports = await response.json();
            if (currentReports.length > initialCount) {
                reportsState = currentReports;
                renderReports(reportsState);
                updateLastScanMetric();

                await fetchDevices();
                fetchAuditLogs();
                finishScan(true, "Subnet scan finalized. Active nodes loaded.");
                return;
            }
        }
    } catch (e) {
        console.error("Polling error:", e);
    }

    setTimeout(() => {
        pollScanCompletion(initialCount, startTime);
    }, 1500);
}

function finishScan(success, message) {
    isScanning = false;
    document.getElementById("scanning-loader").classList.remove("active");
    showToast(message);
}

// On-demand individual device port scan
async function runDevicePortScan(deviceId) {
    if (isScanning) return;

    isScanning = true;

    document.getElementById("scanner-loader-title").innerText = "Scanning Device Ports";
    document.getElementById("scanner-loader-description").innerText = "Running a quick Nmap TCP port sweep (-F) on the active host to identify open services...";
    document.getElementById("scan-progress-text").innerText = "Executing Nmap port analysis tool...";
    document.getElementById("scanning-loader").classList.add("active");

    try {
        const response = await fetch(`/api/devices/${deviceId}/scan-ports`, {
            method: "POST",
            headers: getAuthHeaders()
        });
        if (handleApiError(response)) return;
        if (!response.ok) throw new Error("Port scan request failed.");

        const result = await response.json();

        isScanning = false;
        document.getElementById("scanning-loader").classList.remove("active");
        showToast("Port scan complete.");

        document.getElementById("ports-modal-ip").innerText = result.ip;

        const dev = devicesState.find(d => d.id === deviceId);
        document.getElementById("ports-modal-hostname").innerText = dev ? (dev.hostname || "unknown") : "unknown";

        renderPortsModalList(result.open_ports);
        document.getElementById("modal-ports").classList.add("active");

        fetchDevices();
        fetchAuditLogs();
    } catch (error) {
        console.error("Error scanning ports:", error);
        showToast("Device port scan failed.");
        isScanning = false;
        document.getElementById("scanning-loader").classList.remove("active");
    }
}

// Render open ports inside details modal list (highlight high-risk ports in red)
function renderPortsModalList(ports) {
    const listBody = document.getElementById("ports-list-body");
    if (!listBody) return;

    if (!ports || ports.length === 0) {
        listBody.innerHTML = `
            <tr>
                <td colspan="4" class="ports-empty-state">
                    No open ports detected in the fast range (Top 100).
                </td>
            </tr>
        `;
        return;
    }

    listBody.innerHTML = ports.map(p => {
        const isHighRisk = HIGH_RISK_PORTS.includes(p.port);
        const portBadgeClass = isHighRisk ? 'port-badge-pill high-risk' : 'port-badge-pill';

        return `
            <tr>
                <td class="port-number">
                    <span class="${portBadgeClass}">${p.port}</span>
                </td>
                <td class="port-protocol">${p.protocol}</td>
                <td><span class="badge badge-role">${p.service}</span></td>
                <td>
                    <span class="badge ${isHighRisk ? 'badge-unknown' : 'badge-active'}">
                        <span class="bullet-indicator"></span>
                        ${isHighRisk ? 'High-Risk' : 'Open'}
                    </span>
                </td>
            </tr>
        `;
    }).join('');
}

// View ports helper: parses ports JSON cache and displays modal
// Also parses base64 devices object safely
function viewPorts(deviceBase64) {
    const dev = JSON.parse(decodeURIComponent(escape(atob(deviceBase64))));
    let ports = [];
    try {
        ports = dev.open_ports ? JSON.parse(dev.open_ports) : [];
    } catch (e) {
        console.error("Error parsing ports in viewPorts:", e);
    }

    document.getElementById("ports-modal-ip").innerText = dev.ip;
    document.getElementById("ports-modal-hostname").innerText = dev.hostname || "unknown";

    renderPortsModalList(ports);
    document.getElementById("modal-ports").classList.add("active");
}

// Local Search Filters, Sorting, and Export inside Devices tab
function filterDevices() {
    const query = (document.getElementById("search-devices")?.value || "").toLowerCase().trim();
    const trustFilter = document.getElementById("device-trust-filter")?.value || "";
    const typeFilter = document.getElementById("device-type-filter")?.value || "";
    const deptFilter = document.getElementById("device-dept-filter")?.value || "";

    let filtered = devicesState.filter(dev => {
        // Query search
        const matchQuery = !query ||
            (dev.ip && dev.ip.toLowerCase().includes(query)) ||
            (dev.hostname && dev.hostname.toLowerCase().includes(query)) ||
            (dev.mac && dev.mac.toLowerCase().includes(query)) ||
            (dev.vendor && dev.vendor.toLowerCase().includes(query));

        // Dropdown filters
        const matchTrust = !trustFilter || dev.trust_level === trustFilter;
        const matchType = !typeFilter || dev.os_type === typeFilter;
        const matchDept = !deptFilter || dev.department === deptFilter;

        return matchQuery && matchTrust && matchType && matchDept;
    });

    // Apply client-side sorting
    filtered.sort((a, b) => {
        let valA = a[deviceSortField];
        let valB = b[deviceSortField];

        if (deviceSortField === 'ip') {
            // Natural IP sorting
            const partsA = (valA || '').split('.').map(Number);
            const partsB = (valB || '').split('.').map(Number);
            for (let i = 0; i < 4; i++) {
                const octetA = partsA[i] || 0;
                const octetB = partsB[i] || 0;
                if (octetA !== octetB) {
                    return deviceSortOrder === 'asc' ? octetA - octetB : octetB - octetA;
                }
            }
            return 0;
        }

        // Handle case insensitivity for strings
        if (typeof valA === 'string') valA = valA.toLowerCase();
        if (typeof valB === 'string') valB = valB.toLowerCase();

        // Handle null values
        if (valA === null || valA === undefined) valA = '';
        if (valB === null || valB === undefined) valB = '';

        if (valA < valB) return deviceSortOrder === 'asc' ? -1 : 1;
        if (valA > valB) return deviceSortOrder === 'asc' ? 1 : -1;
        return 0;
    });

    renderDevices(filtered);
}

function toggleDeviceSort(field) {
    if (deviceSortField === field) {
        deviceSortOrder = deviceSortOrder === 'asc' ? 'desc' : 'asc';
    } else {
        deviceSortField = field;
        deviceSortOrder = 'asc';
    }
    updateSortIcons();
    filterDevices();
}

function updateSortIcons() {
    const fields = ['hostname', 'ip', 'vendor', 'last_seen'];
    fields.forEach(f => {
        const el = document.getElementById(`sort-icon-${f}`);
        if (!el) return;
        if (deviceSortField === f) {
            el.innerText = deviceSortOrder === 'asc' ? ' ▲' : ' ▼';
            el.style.color = 'var(--gray-900)';
        } else {
            el.innerText = ' ↕';
            el.style.color = 'var(--color-text-light)';
        }
    });
}

function exportDevicesCSV() {
    // Get currently filtered list of devices by applying the filter logic
    const query = (document.getElementById("search-devices")?.value || "").toLowerCase().trim();
    const trustFilter = document.getElementById("device-trust-filter")?.value || "";
    const typeFilter = document.getElementById("device-type-filter")?.value || "";
    const deptFilter = document.getElementById("device-dept-filter")?.value || "";

    const filtered = devicesState.filter(dev => {
        const matchQuery = !query ||
            (dev.ip && dev.ip.toLowerCase().includes(query)) ||
            (dev.hostname && dev.hostname.toLowerCase().includes(query)) ||
            (dev.mac && dev.mac.toLowerCase().includes(query)) ||
            (dev.vendor && dev.vendor.toLowerCase().includes(query));

        const matchTrust = !trustFilter || dev.trust_level === trustFilter;
        const matchType = !typeFilter || dev.os_type === typeFilter;
        const matchDept = !deptFilter || dev.department === deptFilter;

        return matchQuery && matchTrust && matchType && matchDept;
    });

    if (filtered.length === 0) {
        showToast("No devices to export.");
        return;
    }

    // Generate CSV content
    const headers = [
        "Hostname", "IP Address", "MAC Address", "Vendor", 
        "Trust Level", "OS Type", "Current OS", "Owner", 
        "Department", "Purpose", "Last Seen"
    ];
    
    let csvRows = [headers.join(",")];
    
    filtered.forEach(dev => {
        const row = [
            dev.hostname || "Unknown",
            dev.ip || "",
            dev.mac || "",
            dev.vendor || "Unknown",
            dev.trust_level || "Unknown",
            dev.os_type || "generic",
            dev.current_os || "",
            dev.owner_name || "None",
            dev.department || "None",
            dev.purpose || "",
            dev.last_seen || ""
        ].map(val => {
            // Escape double quotes and wrap in quotes if contains comma
            let formatted = String(val).replace(/"/g, '""');
            if (formatted.includes(",") || formatted.includes("\n") || formatted.includes('"')) {
                formatted = `"${formatted}"`;
            }
            return formatted;
        });
        csvRows.push(row.join(","));
    });

    const csvContent = csvRows.join("\n");
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const blobUrl = URL.createObjectURL(blob);
    
    const a = document.createElement("a");
    a.href = blobUrl;
    a.download = `recon_nds_devices_${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(blobUrl);
    
    showToast("Devices inventory exported successfully.");
}

// Toast Notifications System Helper
function showToast(message, duration = 3000, type = 'info') {
    const container = document.getElementById("toast-container");
    if (!container) return;

    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    
    let iconName = 'info';
    if(type === 'alert' || type === 'error' || type === 'critical') iconName = 'shield-alert';
    else if(type === 'warning') iconName = 'alert-triangle';
    else if(type === 'success') iconName = 'check-circle';

    toast.innerHTML = `
        <div class="toast-icon-wrap"><i data-lucide="${iconName}" style="width: 20px; height: 20px; stroke-width: 2.5px;"></i></div>
        <div class="toast-content">
            ${type === 'critical' || type === 'alert' || type === 'error' ? '<strong>Security Alert</strong>' : ''}
            <span>${message}</span>
        </div>
    `;

    container.appendChild(toast);
    lucide.createIcons();

    setTimeout(() => {
        toast.classList.add("removing");
        toast.addEventListener("animationend", () => {
            toast.remove();
        });
    }, duration);
}

// ==========================================================
// IV. Workstations Telemetry & Alerts Management
// ==========================================================

async function fetchWorkstations() {
    try {
        const response = await fetch("/api/workstations/monitored", { headers: getAuthHeaders() });
        if (handleApiError(response)) return;
        if (!response.ok) throw new Error("Failed to fetch workstations");

        workstationsState = await response.json();

        // Render monitored workstations list
        renderWorkstations(workstationsState);

        // If details view is open, refresh its content live, else select first
        if (activeWorkstationId !== null) {
            fetchWorkstationDetailsTelemetry(activeWorkstationId);
        } else if (workstationsState.length > 0) {
            let listToRender = workstationsState;
            if (currentRole === 'Staff') {
                listToRender = workstationsState.filter(w => w.hostname === 'Workstation-PC' || w.mac === '33:44:55:66:77:88');
            }
            if (listToRender.length > 0) {
                viewWorkstationDetails(listToRender[0].id);
            }
        }
    } catch (error) {
        console.error("Error fetching workstations:", error);
    }
}

async function fetchWorkstationAlerts() {
    try {
        const response = await fetch("/api/workstations/alerts", { headers: getAuthHeaders() });
        if (handleApiError(response)) return;
        if (!response.ok) throw new Error("Failed to fetch threat alerts");

        workstationAlertsState = await response.json();
        renderGlobalAlerts(workstationAlertsState);
    } catch (error) {
        console.error("Error fetching workstation alerts:", error);
    }
}

function renderWorkstations(workstations) {
    const grid = document.getElementById("workstations-list");
    if (!grid) return;

    let listToRender = workstations;
    if (currentRole === 'Staff') {
        // Staff (Jane Doe) can only monitor her own workstation "Workstation-PC"
        listToRender = workstations.filter(w => w.hostname === 'Workstation-PC' || w.mac === '33:44:55:66:77:88');
    }

    if (listToRender.length === 0) {
        grid.innerHTML = `
            <div class="empty-state-row" style="padding: 40px; text-align: center; border: 1px dashed var(--color-border); border-radius: var(--border-radius-lg); background: #ffffff; width: 100%;">
                <i data-lucide="monitor-off" style="width: 48px; height: 48px; color: var(--color-text-light); margin-bottom: 12px;"></i>
                <p style="font-size: 14px; color: var(--color-text-muted);">No monitored workstations found.</p>
                <p style="font-size: 12px; color: var(--color-text-light); margin-top: 4px;">Run workstation_agent.py on client units to initiate live telemetry monitoring.</p>
            </div>
        `;
        lucide.createIcons();
        return;
    }

    grid.innerHTML = listToRender.map(w => {
        const cpu = w.latest_utilization.cpu;
        const ram = w.latest_utilization.ram;

        // Heuristics for progress bar colors
        const getBarClass = (val) => val > 90 ? 'danger' : (val > 70 ? 'warning' : '');

        // Highlight border red if workstation has unresolved threats
        let cardClass = w.status === 'Blocked'
            ? 'workstation-card isolated-card'
            : (w.active_alerts_count > 0 ? 'workstation-card has-threats critical-glow' : 'workstation-card');

        if (w.id === activeWorkstationId) {
            cardClass += ' active';
        }

        const statusText = w.status === 'Blocked' ? 'Isolated' : w.agent_status;
        const statusClass = w.status === 'Blocked' ? 'isolated' : w.agent_status.toLowerCase();

        let alertsHtml = '';
        if (w.active_alerts_count > 0 && w.status !== 'Blocked') {
            const isCritical = workstationAlertsState.some(a => a.device_id === w.id && a.severity === 'Critical');
            const badgeClass = isCritical ? 'card-alert-badge critical-badge' : 'card-alert-badge';
            alertsHtml = `
                <div class="${badgeClass}">
                    <i data-lucide="shield-alert" style="width: 12px; height: 12px;"></i>
                    <span>${w.active_alerts_count} Threat${w.active_alerts_count > 1 ? 's' : ''}</span>
                </div>
            `;
        }

        return `
            <div class="${cardClass}" onclick="viewWorkstationDetails(${w.id})">
                <div class="workstation-card-header">
                    <div class="workstation-card-title">
                        <h4>${w.hostname || 'Unknown Host'}</h4>
                        <span>${w.os_info || 'Unknown OS'}</span>
                    </div>
                    <span class="agent-status-badge ${statusClass}">
                        <span class="pulse-dot" style="display: ${statusText === 'Online' ? 'inline-block' : 'none'}; width: 6px; height: 6px; margin-right: 4px;"></span>
                        ${statusText}
                    </span>
                </div>
                
                <div class="workstation-card-meta">
                    <div>IP: <code>${w.ip}</code></div>
                    <div>MAC: <code>${w.mac || 'N/A'}</code></div>
                </div>
                
                <div class="workstation-card-resources">
                    <div class="resource-bar-row">
                        <div class="resource-bar-label">
                            <span>CPU</span>
                            <span>${w.is_monitored ? cpu.toFixed(1) + '%' : 'Offline'}</span>
                        </div>
                        <div class="resource-bar-track">
                            <div class="resource-bar-fill ${getBarClass(cpu)}" style="width: ${w.is_monitored ? cpu : 0}%;"></div>
                        </div>
                    </div>
                    <div class="resource-bar-row">
                        <div class="resource-bar-label">
                            <span>RAM</span>
                            <span>${w.is_monitored ? ram.toFixed(1) + '%' : 'Offline'}</span>
                        </div>
                        <div class="resource-bar-track">
                            <div class="resource-bar-fill ${getBarClass(ram)}" style="width: ${w.is_monitored ? ram : 0}%;"></div>
                        </div>
                    </div>
                </div>
                
                <div class="workstation-card-footer">
                    <span>Last contact: ${formatFriendlyTime(w.last_contact)}</span>
                    ${alertsHtml}
                </div>
            </div>
        `;
    }).join('');

    lucide.createIcons();
}

function renderGlobalAlerts(alerts) {
    const banner = document.getElementById("workstations-alerts-banner-container");
    const list = document.getElementById("global-alerts-list");
    const countBadge = document.getElementById("active-threats-count");

    if (!banner || !list) return;

    let filteredAlerts = alerts;
    if (currentRole === 'Staff') {
        // Filter alerts for Staff's own host
        filteredAlerts = alerts.filter(a => a.hostname === 'Workstation-PC');
    }

    if (filteredAlerts.length === 0) {
        banner.style.display = "none";
        return;
    }

    banner.style.display = "block";
    countBadge.innerText = `${filteredAlerts.length} Active Threat${filteredAlerts.length > 1 ? 's' : ''}`;

    list.innerHTML = filteredAlerts.map(a => {
        const severityClass = a.severity.toLowerCase();

        let actionBtn = '';
        if (currentRole !== 'Staff') {
            actionBtn = `<button class="btn-resolve-alert" onclick="openResolveAlertModal(${a.id}, event)">Resolve</button>`;
        }

        return `
            <div class="alert-threat-card">
                <div class="alert-threat-content">
                    <div class="alert-threat-icon-wrapper ${severityClass}">
                        <i data-lucide="shield-alert" style="width: 20px; height: 20px;"></i>
                    </div>
                    <div class="alert-threat-details">
                        <h5>${a.title}</h5>
                        <p>${a.description}</p>
                        <div class="alert-threat-meta">
                            <span>Host: <strong>${a.hostname}</strong></span>
                            <span>IP: <code>${a.ip}</code></span>
                            <span class="alert-time">
                                <i data-lucide="clock" style="width: 12px; height: 12px;"></i>
                                ${formatFriendlyTime(a.timestamp)}
                            </span>
                        </div>
                    </div>
                </div>
                ${actionBtn}
            </div>
        `;
    }).join('');

    lucide.createIcons();
}

async function viewWorkstationDetails(id) {
    activeWorkstationId = id;

    // Update active class in list
    renderWorkstations(workstationsState);

    // Show details pane
    const detailsPane = document.getElementById("workstation-details-pane");
    if (detailsPane) {
        detailsPane.style.display = "block";
        detailsPane.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    // Default details tab to processes
    switchDetailsTab('processes');

    // Fetch live details
    await fetchWorkstationDetailsTelemetry(id);
}

function backToWorkstationsList() {
    activeWorkstationId = null;

    // Switch UI views
    document.getElementById("workstation-details-pane").style.display = "none";
    document.getElementById("workstations-grid-view").style.display = "block";

    fetchWorkstations();
}

async function fetchWorkstationDetailsTelemetry(id) {
    try {
        const response = await fetch(`/api/workstations/${id}/telemetry`, { headers: getAuthHeaders() });
        if (handleApiError(response)) return;
        if (!response.ok) throw new Error("Failed to fetch detailed telemetry");

        const data = await response.json();

        // Find basic workstation status in state
        const ws = workstationsState.find(w => w.id === id);
        if (!ws) return;

        // Update header details
        document.getElementById("details-hostname").innerText = ws.hostname || "Unknown Workstation";
        document.getElementById("details-os").innerText = data.latest ? (data.latest.os_info || "Unknown OS") : "Offline / Unmonitored";
        document.getElementById("details-ip").innerText = ws.ip;
        document.getElementById("details-mac").innerText = ws.mac || "N/A";

        // Manage Isolation Button
        const isolationStatus = document.getElementById("details-isolation-status");
        const btnIsolate = document.getElementById("btn-isolate-host");

        if (ws.status === 'Blocked') {
            isolationStatus.style.display = "inline-block";
            if (btnIsolate) btnIsolate.style.display = "none";
        } else {
            isolationStatus.style.display = "none";
            if (btnIsolate) {
                btnIsolate.style.display = currentRole === 'Staff' ? "none" : "inline-flex";
            }
        }

        // If telemetry exists, populate resource gauges and tables
        if (data.has_telemetry && data.latest) {
            const cpu = data.latest.cpu_usage;
            const ram = data.latest.ram_usage;

            // Set gauge text
            document.getElementById("gauge-cpu-val").innerText = cpu.toFixed(1) + "%";
            document.getElementById("gauge-ram-val").innerText = ram.toFixed(1) + "%";

            // Set progress bars
            const cpuBar = document.getElementById("gauge-cpu-bar");
            const ramBar = document.getElementById("gauge-ram-bar");

            cpuBar.style.width = cpu + "%";
            ramBar.style.width = ram + "%";

            // Manage color classes
            cpuBar.className = "progress-bar " + (cpu > 90 ? "danger" : (cpu > 70 ? "warning" : ""));
            ramBar.className = "progress-bar " + (ram > 90 ? "danger" : (ram > 70 ? "warning" : ""));

            // Render specific tables
            renderProcessesList(data.latest.running_processes);
            renderNetworkConnectionsList(data.latest.network_connections);
            renderUsbDevicesList(data.latest.usb_devices);
            renderSessionsList(data.latest.logged_in_users);
        } else {
            // Default empty resource state
            document.getElementById("gauge-cpu-val").innerText = "0%";
            document.getElementById("gauge-ram-val").innerText = "0%";
            document.getElementById("gauge-cpu-bar").style.width = "0%";
            document.getElementById("gauge-ram-bar").style.width = "0%";

            // Empty tables
            const emptyTableHtml = `<tr><td colspan="10" class="empty-state-row" style="text-align: center; color: var(--color-text-light);">No live telemetry data received from agent.</td></tr>`;
            document.getElementById("details-processes-list").innerHTML = emptyTableHtml;
            document.getElementById("details-network-list").innerHTML = emptyTableHtml;
            document.getElementById("details-usb-list").innerHTML = emptyTableHtml;
            document.getElementById("details-sessions-list").innerHTML = emptyTableHtml;
        }

    } catch (error) {
        console.error("Error fetching workstation telemetry details:", error);
    }
}

let runningProcessesCache = [];

function renderProcessesList(processes) {
    runningProcessesCache = processes || [];
    filterProcesses(); // Call filter to handle initial load and rendering
}

function filterProcesses() {
    const listBody = document.getElementById("details-processes-list");
    if (!listBody) return;

    const query = document.getElementById("search-processes").value.toLowerCase().trim();

    const filtered = runningProcessesCache.filter(p => {
        return !query ||
            p.name.toLowerCase().includes(query) ||
            String(p.pid).includes(query) ||
            (p.command_line && p.command_line.toLowerCase().includes(query));
    });

    if (filtered.length === 0) {
        listBody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--color-text-light); padding: 16px;">No matching running processes.</td></tr>`;
        return;
    }

    const SUSPICIOUS_PROC_LIST = ["mimikatz.exe", "mimikatz", "pypykatz", "nc.exe", "nc", "netcat", "nmap", "nmap.exe", "wireshark.exe", "tshark", "responder", "hydra", "john.exe", "john", "metasploit", "xmrig.exe", "xmrig"];
    const SUSPICIOUS_CMD_WORDS = ["-encodedcommand", "-enc", "vssadmin", "shadowcopy", "downloadstring", "invoke-expression"];

    listBody.innerHTML = filtered.map(p => {
        let isSuspicious = false;
        let details = "Clean";
        let badgeClass = "clean";

        const nameLower = p.name.toLowerCase();
        const cmdLower = (p.command_line || "").toLowerCase();

        // Heuristic mapping matching backend
        if (SUSPICIOUS_PROC_LIST.includes(nameLower) || SUSPICIOUS_PROC_LIST.some(w => nameLower.includes(w))) {
            isSuspicious = true;
            details = "Malicious Binary";
            badgeClass = "alert-flagged";
        } else if (SUSPICIOUS_CMD_WORDS.some(w => cmdLower.includes(w))) {
            isSuspicious = true;
            details = "Suspicious Arguments";
            badgeClass = "suspicious";
        }

        return `
            <tr style="${isSuspicious ? 'background-color: #fef2f2;' : ''}">
                <td><code>${p.pid}</code></td>
                <td style="font-weight: 600;">${p.name}</td>
                <td><code style="font-size: 11px; max-width: 450px; display: block; overflow-wrap: break-word;">${p.command_line || 'N/A'}</code></td>
                <td><span class="process-sec-badge ${badgeClass}">${details}</span></td>
            </tr>
        `;
    }).join('');
}

function renderNetworkConnectionsList(connections) {
    const listBody = document.getElementById("details-network-list");
    if (!listBody) return;

    if (!connections || connections.length === 0) {
        listBody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--color-text-light); padding: 16px;">No active connections.</td></tr>`;
        return;
    }

    const SUSPICIOUS_PORTS_LIST = [4444, 31337, 6667, 5555, 9999];

    listBody.innerHTML = connections.map(c => {
        const isSuspicious = SUSPICIOUS_PORTS_LIST.includes(c.remote_port) || (c.state === 'LISTEN' && SUSPICIOUS_PORTS_LIST.includes(c.local_port));
        const badgeClass = isSuspicious ? "process-sec-badge suspicious" : "process-sec-badge clean";
        const checkText = isSuspicious ? "Suspicious Port" : "Verified Safe";

        return `
            <tr style="${isSuspicious ? 'background-color: #fef2f2;' : ''}">
                <td><strong>${c.protocol}</strong></td>
                <td><code>${c.local_ip}:${c.local_port}</code></td>
                <td><code>${c.remote_ip}:${c.remote_port}</code></td>
                <td><span class="badge ${c.state === 'ESTABLISHED' ? 'badge-active' : 'badge-inactive'}">${c.state}</span></td>
                <td><span class="${badgeClass}">${checkText}</span></td>
            </tr>
        `;
    }).join('');
}

function renderUsbDevicesList(usbs) {
    const listBody = document.getElementById("details-usb-list");
    if (!listBody) return;

    if (!usbs || usbs.length === 0) {
        listBody.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--color-text-light); padding: 16px;">No USB devices registered.</td></tr>`;
        return;
    }

    listBody.innerHTML = usbs.map(u => {
        const desc = u.description.toLowerCase();
        const isMalicious = desc.includes("rubber ducky") || desc.includes("hak5") || desc.includes("bash bunny");
        const isStorage = desc.includes("mass storage") || desc.includes("sandisk") || desc.includes("kingston") || desc.includes("cruzer") || desc.includes("usb drive");

        let badgeClass = "process-sec-badge clean";
        let checkText = "Approved HID";

        if (isMalicious) {
            badgeClass = "process-sec-badge alert-flagged";
            checkText = "Keystroke Injector Threat";
        } else if (isStorage) {
            badgeClass = "process-sec-badge suspicious";
            checkText = "Storage Drive Connection";
        }

        return `
            <tr style="${isMalicious ? 'background-color: #fef2f2;' : (isStorage ? 'background-color: #fff7ed;' : '')}">
                <td style="font-weight: 600;">${u.description}</td>
                <td>${u.class || 'Unknown'}</td>
                <td><code>${u.device_id}</code></td>
                <td><span class="${badgeClass}">${checkText}</span></td>
            </tr>
        `;
    }).join('');
}

function renderSessionsList(sessions) {
    const listBody = document.getElementById("details-sessions-list");
    if (!listBody) return;

    if (!sessions || sessions.length === 0) {
        listBody.innerHTML = `<tr><td colspan="3" style="text-align: center; color: var(--color-text-light); padding: 16px;">No active login sessions.</td></tr>`;
        return;
    }

    listBody.innerHTML = sessions.map(s => {
        const isRdpAdmin = s.username.toLowerCase() === 'administrator' && (s.session_type.toLowerCase().includes('rdp') || s.session_type.toLowerCase().includes('remote'));
        return `
            <tr style="${isRdpAdmin ? 'background-color: #fef2f2;' : ''}">
                <td style="font-weight: 600;">
                    <i data-lucide="user" style="width: 14px; height: 14px; display: inline; vertical-align: middle; margin-right: 6px;"></i>
                    ${s.username}
                </td>
                <td>${s.session_type}</td>
                <td>
                    <span class="badge ${isRdpAdmin ? 'badge-blocked' : 'badge-active'}">
                        ${isRdpAdmin ? 'High-Risk remote' : 'Logged In'}
                    </span>
                </td>
            </tr>
        `;
    }).join('');

    lucide.createIcons();
}

function switchDetailsTab(tabName) {
    activeDetailsTab = tabName;

    // Toggle active classes on tab buttons
    document.querySelectorAll(".details-tab-btn").forEach(btn => btn.classList.remove("active"));
    const tabBtnMap = {
        'processes': 'btn-dt-processes',
        'network': 'btn-dt-network',
        'usb': 'btn-dt-usb',
        'sessions': 'btn-dt-sessions'
    };
    if (tabBtnMap[tabName]) {
        document.getElementById(tabBtnMap[tabName]).classList.add("active");
    }

    // Toggle active classes on tab panels
    document.querySelectorAll(".details-pane").forEach(pane => pane.classList.remove("active"));
    document.getElementById(`details-tab-${tabName}`).classList.add("active");
}

function openResolveAlertModal(alertId, event) {
    if (event) event.stopPropagation(); // Avoid triggering card details click

    const alert = workstationAlertsState.find(a => a.id === alertId);
    if (!alert) return;

    document.getElementById("resolve-alert-id").value = alertId;
    document.getElementById("resolve-alert-title").innerText = alert.title;
    document.getElementById("resolve-alert-desc").innerText = alert.description;
    document.getElementById("resolve-alert-host").innerText = alert.hostname || "unknown";
    document.getElementById("resolve-alert-severity").innerText = alert.severity;

    // Map badge color based on severity
    const badge = document.getElementById("resolve-alert-severity");
    badge.className = "badge " + (alert.severity === 'Critical' ? 'badge-blocked' : (alert.severity === 'High' ? 'badge-unknown' : 'badge-role'));

    document.getElementById("resolve-notes").value = "";

    document.getElementById("modal-resolve-alert").classList.add("active");
}

async function submitResolveAlert(event) {
    event.preventDefault();

    const alertId = document.getElementById("resolve-alert-id").value;
    const notes = document.getElementById("resolve-notes").value.trim();

    try {
        const response = await fetch(`/api/workstations/alerts/${alertId}/resolve`, {
            method: "POST",
            headers: getAuthHeaders(),
            body: JSON.stringify({ resolution_notes: notes })
        });

        if (handleApiError(response)) return;
        if (!response.ok) throw new Error("Resolution request failed");

        showToast("Security alert resolved and cleared.");
        closeModal("modal-resolve-alert");

        // Refresh telemetry
        fetchWorkstations();
        fetchWorkstationAlerts();
        fetchAuditLogs();
    } catch (error) {
        console.error("Error resolving alert:", error);
        showToast("Failed to resolve threat alert.");
    }
}

async function triggerHostIsolation() {
    if (activeWorkstationId === null) return;
    const ws = workstationsState.find(w => w.id === activeWorkstationId);
    if (!ws) return;

    if (!confirm(`CRITICAL WARNING: Are you sure you want to ISOLATE '${ws.hostname}' from the production network? This will block all local and outbound network transport for this machine at the switch NAC port level.`)) {
        return;
    }

    try {
        const response = await fetch(`/api/workstations/${activeWorkstationId}/isolate`, {
            method: "POST",
            headers: getAuthHeaders()
        });

        if (handleApiError(response)) return;
        if (!response.ok) throw new Error("Isolation request failed");

        showToast(`Host ${ws.hostname} has been successfully ISOLATED.`);

        // Refresh detail view and grid
        fetchWorkstations();
        fetchWorkstationAlerts();
        fetchAuditLogs();
    } catch (error) {
        console.error("Error isolating host:", error);
        showToast("Host isolation trigger failed.");
    }
}

// ==========================================
// VII. Dashboard, Export, Filter & Inactivity
// ==========================================

// Chart instances (stored to allow re-rendering without duplication)
let chartTrust = null;
let chartDept = null;
let chartScans = null;
let chartOs = null;

async function fetchDashboardStats() {
    try {
        const response = await fetch("/api/dashboard/stats", { headers: getAuthHeaders() });
        if (handleApiError(response)) return;
        if (!response.ok) throw new Error("Failed to fetch dashboard stats");
        const data = await response.json();
        renderDashboardCharts(data);
    } catch (error) {
        console.error("Error fetching dashboard stats:", error);
    }
}

function renderDashboardCharts(data) {
    // Update KPI cards
    const kpiTotal = document.getElementById("kpi-total");
    const kpiPct = document.getElementById("kpi-trusted-pct");
    const kpiAlerts = document.getElementById("kpi-alerts");
    const kpiActive = document.getElementById("kpi-active");
    if (kpiTotal) kpiTotal.innerText = data.total_devices ?? 0;
    if (kpiPct) kpiPct.innerText = (data.trusted_percent ?? 0) + "%";
    if (kpiAlerts) kpiAlerts.innerText = data.active_alerts ?? 0;
    if (kpiActive) kpiActive.innerText = data.active_devices ?? 0;

    // Also update sidebar alert badge
    updateAlertBadge(data.active_alerts ?? 0);

    const chartDefaults = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                labels: { color: '#64748b', font: { family: 'Inter', size: 12, weight: '500' } }
            }
        }
    };

    const trustColors = ['#10b981', '#f59e0b', '#ef4444', '#64748b'];
    const trust = data.trust_distribution;

    // 1. Doughnut: Trust Level
    const ctxTrust = document.getElementById("chart-trust");
    if (ctxTrust) {
        if (chartTrust) chartTrust.destroy();
        chartTrust = new Chart(ctxTrust, {
            type: 'doughnut',
            data: {
                labels: ['Trusted', 'Unknown', 'Blocked', 'Pending'],
                datasets: [{
                    data: [trust.Trusted, trust.Unknown, trust.Blocked, trust.Pending],
                    backgroundColor: trustColors,
                    borderColor: '#ffffff',
                    borderWidth: 2
                }]
            },
            options: {
                ...chartDefaults,
                cutout: '65%',
                plugins: {
                    ...chartDefaults.plugins,
                    legend: { position: 'bottom', labels: { color: '#64748b', font: { family: 'Inter', size: 11 }, padding: 16 } }
                }
            }
        });
    }

    // 2. Bar: Devices by Department
    const ctxDept = document.getElementById("chart-dept");
    if (ctxDept) {
        if (chartDept) chartDept.destroy();
        const ctx2d = ctxDept.getContext('2d');
        const gradient = ctx2d.createLinearGradient(0, 0, 0, 220);
        gradient.addColorStop(0, 'rgba(99, 102, 241, 0.85)'); // Indigo
        gradient.addColorStop(1, 'rgba(99, 102, 241, 0.15)');

        chartDept = new Chart(ctxDept, {
            type: 'bar',
            data: {
                labels: data.department_distribution.labels,
                datasets: [{
                    label: 'Devices',
                    data: data.department_distribution.values,
                    backgroundColor: gradient,
                    borderColor: '#6366f1',
                    borderWidth: 1,
                    borderRadius: 6
                }]
            },
            options: {
                ...chartDefaults,
                scales: {
                    x: { ticks: { color: '#64748b' }, grid: { color: '#f1f5f9' } },
                    y: { ticks: { color: '#64748b', stepSize: 1 }, grid: { color: '#f1f5f9' } }
                },
                plugins: { legend: { display: false } }
            }
        });
    }

    // 3. Line: Scan history last 7 days
    const ctxScans = document.getElementById("chart-scans");
    if (ctxScans) {
        if (chartScans) chartScans.destroy();
        const ctx2d = ctxScans.getContext('2d');
        const gradient = ctx2d.createLinearGradient(0, 0, 0, 200);
        gradient.addColorStop(0, 'rgba(16, 185, 129, 0.22)'); // Emerald
        gradient.addColorStop(1, 'rgba(16, 185, 129, 0.00)');

        chartScans = new Chart(ctxScans, {
            type: 'line',
            data: {
                labels: data.scan_history.dates.length > 0 ? data.scan_history.dates : ['No data'],
                datasets: [{
                    label: 'Scans',
                    data: data.scan_history.counts.length > 0 ? data.scan_history.counts : [0],
                    borderColor: '#10b981',
                    backgroundColor: gradient,
                    fill: true,
                    tension: 0.4,
                    pointBackgroundColor: '#10b981',
                    pointBorderColor: '#ffffff',
                    pointBorderWidth: 2,
                    pointRadius: 5,
                    pointHoverRadius: 7
                }]
            },
            options: {
                ...chartDefaults,
                scales: {
                    x: { ticks: { color: '#64748b' }, grid: { color: '#f1f5f9' } },
                    y: { ticks: { color: '#64748b', stepSize: 1 }, grid: { color: '#f1f5f9' }, beginAtZero: true }
                },
                plugins: { legend: { display: false } }
            }
        });
    }

    // 4. Horizontal bar: OS/Device type
    const ctxOs = document.getElementById("chart-os");
    if (ctxOs) {
        if (chartOs) chartOs.destroy();
        const ctx2d = ctxOs.getContext('2d');
        const gradient = ctx2d.createLinearGradient(0, 0, 300, 0); // Horizontal gradient
        gradient.addColorStop(0, 'rgba(20, 184, 166, 0.85)'); // Teal
        gradient.addColorStop(1, 'rgba(14, 165, 233, 0.35)'); // Cyan

        chartOs = new Chart(ctxOs, {
            type: 'bar',
            data: {
                labels: data.os_distribution.labels,
                datasets: [{
                    label: 'Devices',
                    data: data.os_distribution.values,
                    backgroundColor: gradient,
                    borderColor: '#14b8a6',
                    borderWidth: 1,
                    borderRadius: 6
                }]
            },
            options: {
                ...chartDefaults,
                indexAxis: 'y',
                scales: {
                    x: { ticks: { color: '#64748b', stepSize: 1 }, grid: { color: '#f1f5f9' }, beginAtZero: true },
                    y: { ticks: { color: '#64748b' }, grid: { display: false } }
                },
                plugins: { legend: { display: false } }
            }
        });
    }
}

// Update the workstation alert badge on the sidebar nav
function updateAlertBadge(count) {
    const badge = document.getElementById("workstation-alert-badge");
    if (!badge) return;
    if (count > 0) {
        badge.innerText = count > 99 ? '99+' : count;
        badge.style.display = 'inline-flex';
    } else {
        badge.style.display = 'none';
    }
}

// Export CSV — calls backend export endpoint and triggers download
function exportCSV(type) {
    if (!authToken) return;
    const endpoints = {
        reports: '/api/reports/export/csv',
        audit: '/api/audit/export/csv'
    };
    const url = endpoints[type];
    if (!url) return;

    // Create a temporary anchor to trigger download with auth header via fetch
    fetch(url, { headers: getAuthHeaders() })
        .then(response => {
            if (!response.ok) throw new Error("Export failed");
            const disposition = response.headers.get('Content-Disposition');
            let filename = type === 'reports' ? 'recon_nds_scan_reports.csv' : 'recon_nds_audit_logs.csv';
            if (disposition) {
                const match = disposition.match(/filename=([^;]+)/);
                if (match) filename = match[1].trim();
            }
            return response.blob().then(blob => ({ blob, filename }));
        })
        .then(({ blob, filename }) => {
            const blobUrl = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = blobUrl;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(blobUrl);
            showToast(`${type === 'reports' ? 'Scan Reports' : 'Audit Logs'} exported successfully.`);
        })
        .catch(err => {
            console.error("Export error:", err);
            showToast("Export failed. Please try again.");
        });
}

// Client-side filter for Audit Logs table
function filterAuditLogs() {
    const searchVal = (document.getElementById("search-audit")?.value || "").toLowerCase();
    const actionFilter = (document.getElementById("audit-action-filter")?.value || "").toUpperCase();

    const filtered = auditState.filter(log => {
        const matchAction = !actionFilter || (log.action || "").toUpperCase() === actionFilter;
        const matchSearch = !searchVal ||
            (log.username || "").toLowerCase().includes(searchVal) ||
            (log.action || "").toLowerCase().includes(searchVal) ||
            (log.target || "").toLowerCase().includes(searchVal) ||
            (log.details || "").toLowerCase().includes(searchVal) ||
            (log.role || "").toLowerCase().includes(searchVal);
        return matchAction && matchSearch;
    });

    renderAuditLogs(filtered);
}

// Client-side filter for Reports table
function filterReports() {
    const searchVal = (document.getElementById("search-reports")?.value || "").toLowerCase();

    const filtered = reportsState.filter(rep => {
        return !searchVal ||
            (rep.summary || "").toLowerCase().includes(searchVal) ||
            String(rep.devices_found || "").includes(searchVal) ||
            String(rep.active_devices || "").includes(searchVal);
    });

    renderReports(filtered);
}

// ==========================================
// VIII. Session Inactivity Timeout (30 min)
// ==========================================

let inactivityTimer = null;
const INACTIVITY_LIMIT_MS = 30 * 60 * 1000; // 30 minutes

function resetInactivityTimer() {
    if (inactivityTimer) clearTimeout(inactivityTimer);
    if (!authToken) return; // Don't run if logged out
    inactivityTimer = setTimeout(() => {
        showToast("Session expired due to inactivity. Please sign in again.");
        setTimeout(() => logout(), 1500);
    }, INACTIVITY_LIMIT_MS);
}

function startInactivityTimer() {
    ['mousemove', 'keydown', 'click', 'scroll', 'touchstart'].forEach(event => {
        document.addEventListener(event, resetInactivityTimer, { passive: true });
    });
    resetInactivityTimer();
}

// ==========================================
// IX. Employees (HR Profiles)
// ==========================================

async function fetchEmployees() {
    try {
        const response = await fetch('/api/employees/', { headers: getAuthHeaders() });
        if (handleApiError(response)) return;
        if (!response.ok) throw new Error('Failed to fetch employees');
        employeesState = await response.json();
        renderEmployees(employeesState);
    } catch (error) {
        console.error('Employees fetch error:', error);
    }
}

function renderEmployees(employees) {
    const listBody = document.getElementById('employees-list-body');
    if (!listBody) return;

    if (!employees || employees.length === 0) {
        listBody.innerHTML = `<tr><td colspan="9" class="users-empty">No employee profiles registered yet.</td></tr>`;
        return;
    }

    const isSuperAdmin = currentRole === 'super_admin';

    listBody.innerHTML = employees.map(emp => {
        const statusBadge = emp.is_active
            ? `<span class="badge badge-active">Active</span>`
            : `<span class="badge badge-inactive">Inactive</span>`;
        const linkedUser = emp.linked_username
            ? `<code class="reports-subnet">${emp.linked_username}</code>`
            : `<span class="users-locked">None</span>`;
        const actionsBtns = isSuperAdmin ? `
            <button class="btn-danger-text" onclick="deleteEmployee(${emp.id})">Remove</button>
        ` : `<span class="users-locked">View Only</span>`;

        return `
            <tr>
                <td><code class="reports-subnet">${emp.employee_id || 'N/A'}</code></td>
                <td class="users-username">${emp.full_name}</td>
                <td>${emp.position || 'N/A'}</td>
                <td><span class="badge badge-role">${emp.department || 'N/A'}</span></td>
                <td>${emp.email || 'N/A'}</td>
                <td>${emp.date_hired || 'N/A'}</td>
                <td>${linkedUser}</td>
                <td>${statusBadge}</td>
                <td class="actions-col">${actionsBtns}</td>
            </tr>
        `;
    }).join('');

    lucide.createIcons();
}

function filterEmployees() {
    const search = (document.getElementById('search-employees')?.value || '').toLowerCase();
    const filtered = employeesState.filter(e => {
        return !search ||
            (e.full_name || '').toLowerCase().includes(search) ||
            (e.department || '').toLowerCase().includes(search) ||
            (e.position || '').toLowerCase().includes(search) ||
            (e.employee_id || '').toLowerCase().includes(search);
    });
    renderEmployees(filtered);
}

async function saveEmployee(event) {
    event.preventDefault();

    const editId = document.getElementById('edit-employee-id').value;
    const isEdit = editId !== '';

    const data = {
        employee_id: document.getElementById('emp-id').value.trim() || null,
        full_name: document.getElementById('emp-fullname').value.trim(),
        position: document.getElementById('emp-position').value.trim() || null,
        department: document.getElementById('emp-dept').value || null,
        email: document.getElementById('emp-email').value.trim() || null,
        phone: document.getElementById('emp-phone').value.trim() || null,
        date_hired: document.getElementById('emp-hired').value || null,
        user_id: document.getElementById('emp-user-id').value ? parseInt(document.getElementById('emp-user-id').value) : null,
    };

    try {
        const url = isEdit ? `/api/employees/${editId}` : '/api/employees/';
        const method = isEdit ? 'PUT' : 'POST';
        const response = await fetch(url, {
            method,
            headers: getAuthHeaders(),
            body: JSON.stringify(data)
        });

        if (handleApiError(response)) return;
        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.detail || 'Save failed');
        }

        showToast(isEdit ? 'Employee profile updated.' : 'Employee registered successfully.');
        closeModal('modal-employee');
        fetchEmployees();
        fetchAuditLogs();
    } catch (error) {
        showToast(`Failed: ${error.message}`);
    }
}

async function deleteEmployee(empId) {
    if (!confirm('Delete this employee profile?')) return;

    try {
        const response = await fetch(`/api/employees/${empId}`, {
            method: 'DELETE',
            headers: getAuthHeaders()
        });
        if (handleApiError(response)) return;
        if (!response.ok) throw new Error('Delete failed');

        showToast('Employee profile deleted.');
        fetchEmployees();
        fetchAuditLogs();
    } catch (error) {
        showToast(`Failed: ${error.message}`);
    }
}

// ==========================================
// X. Workspaces
// ==========================================

async function fetchWorkspaces() {
    try {
        const response = await fetch('/api/workspaces/', { headers: getAuthHeaders() });
        if (handleApiError(response)) return;
        if (!response.ok) throw new Error('Failed to fetch workspaces');
        workspacesState = await response.json();
        renderWorkspaces(workspacesState);
    } catch (error) {
        console.error('Workspaces fetch error:', error);
    }
}

function renderWorkspaces(workspaces) {
    const grid = document.getElementById('workspaces-grid');
    if (!grid) return;

    if (!workspaces || workspaces.length === 0) {
        grid.innerHTML = `<div class="users-empty" style="grid-column: 1/-1; text-align:center; padding:40px;">No workspaces configured yet.</div>`;
        return;
    }

    const isSuperAdmin = currentRole === 'super_admin';
    const isOperator = currentRole === 'operator';
    const canEdit = isSuperAdmin || isOperator;

    grid.innerHTML = workspaces.map(ws => {
        const devicePills = (ws.devices || []).map(dev => `
            <span class="workspace-device-pill">
                <i data-lucide="monitor"></i>
                ${dev.hostname || dev.ip}
            </span>
        `).join('');

        const deleteBtn = isSuperAdmin
            ? `<button class="btn btn-danger btn-sm" onclick="deleteWorkspace(${ws.id})" style="font-size:12px;padding:5px 10px;">Delete</button>`
            : '';

        return `
            <div class="workspace-card">
                <div class="workspace-card-header">
                    <div>
                        <div class="workspace-card-title">${ws.name}</div>
                        <div class="workspace-card-location">
                            <i data-lucide="map-pin"></i>
                            ${ws.location || 'Location not specified'}
                        </div>
                    </div>
                    <div class="workspace-icon-wrap">
                        <i data-lucide="building-2"></i>
                    </div>
                </div>
                ${ws.description ? `<div class="workspace-card-desc">${ws.description}</div>` : ''}
                <div class="workspace-devices-section">
                    <div class="workspace-devices-header">
                        <i data-lucide="monitor" style="width:12px;height:12px;vertical-align:middle;"></i>
                        ${ws.device_count || 0} Device${(ws.device_count || 0) !== 1 ? 's' : ''} Assigned
                    </div>
                    <div>${devicePills || '<span style="font-size:12px;color:var(--gray-400);">No devices assigned</span>'}</div>
                </div>
                ${canEdit ? `
                <div class="workspace-card-actions">
                    ${deleteBtn}
                    <button class="btn btn-secondary btn-sm" onclick="openAddDeviceToWorkspace(${ws.id})" style="font-size:12px;padding:5px 10px;">
                        <i data-lucide="plus"></i> Add Device
                    </button>
                </div>` : ''}
            </div>
        `;
    }).join('');

    lucide.createIcons();
}

async function saveWorkspace(event) {
    event.preventDefault();
    const editId = document.getElementById('edit-workspace-id').value;
    const isEdit = editId !== '';

    const data = {
        name: document.getElementById('ws-name').value.trim(),
        location: document.getElementById('ws-location').value.trim() || null,
        description: document.getElementById('ws-description').value.trim() || null,
    };

    try {
        const url = isEdit ? `/api/workspaces/${editId}` : '/api/workspaces/';
        const method = isEdit ? 'PUT' : 'POST';
        const response = await fetch(url, {
            method,
            headers: getAuthHeaders(),
            body: JSON.stringify(data)
        });
        if (handleApiError(response)) return;
        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.detail || 'Save failed');
        }

        showToast(isEdit ? 'Workspace updated.' : 'Workspace created successfully.');
        closeModal('modal-workspace');
        fetchWorkspaces();
        fetchAuditLogs();
    } catch (error) {
        showToast(`Failed: ${error.message}`);
    }
}

async function deleteWorkspace(wsId) {
    if (!confirm('Delete this workspace? Devices will be unassigned but not deleted.')) return;

    try {
        const response = await fetch(`/api/workspaces/${wsId}`, {
            method: 'DELETE',
            headers: getAuthHeaders()
        });
        if (handleApiError(response)) return;
        if (!response.ok) throw new Error('Delete failed');

        showToast('Workspace deleted.');
        fetchWorkspaces();
        fetchAuditLogs();
    } catch (error) {
        showToast(`Failed: ${error.message}`);
    }
}

let activeWorkspaceId = null;

async function openAddDeviceToWorkspace(wsId) {
    activeWorkspaceId = wsId;
    
    // Clear search input
    const searchInput = document.getElementById('ws-device-search');
    if (searchInput) searchInput.value = '';
    
    // Render list
    renderWorkspaceDeviceList();
    
    // Open modal
    openModal('modal-add-workspace-device');
}

function filterWorkspaceDevices() {
    const query = document.getElementById('ws-device-search')?.value || '';
    renderWorkspaceDeviceList(query);
}

function renderWorkspaceDeviceList(query = '') {
    const listContainer = document.getElementById('ws-device-list');
    if (!listContainer) return;

    if (!devicesState || devicesState.length === 0) {
        listContainer.innerHTML = '<div class="ws-device-list-empty">No discovered devices available.</div>';
        return;
    }

    // Find the current workspace to identify its devices
    const currentWorkspace = workspacesState.find(w => w.id === activeWorkspaceId);
    const currentWorkspaceDeviceIds = new Set((currentWorkspace?.devices || []).map(d => d.id));

    // Map device IDs to other workspaces
    const otherWorkspacesMap = {};
    workspacesState.forEach(ws => {
        if (ws.id !== activeWorkspaceId) {
            (ws.devices || []).forEach(d => {
                otherWorkspacesMap[d.id] = ws.name;
            });
        }
    });

    const lowerQuery = query.toLowerCase().trim();

    // Filter and map devices
    const filtered = devicesState.filter(d => {
        // Exclude devices already in the target workspace
        if (currentWorkspaceDeviceIds.has(d.id)) return false;

        // Apply search query filter
        if (lowerQuery) {
            const host = (d.hostname || '').toLowerCase();
            const ip = (d.ip || '').toLowerCase();
            const vendor = (d.vendor || '').toLowerCase();
            return host.includes(lowerQuery) || ip.includes(lowerQuery) || vendor.includes(lowerQuery);
        }
        return true;
    });

    if (filtered.length === 0) {
        listContainer.innerHTML = '<div class="ws-device-list-empty">No matching devices found.</div>';
        return;
    }

    listContainer.innerHTML = filtered.map(d => {
        const assignedWS = otherWorkspacesMap[d.id];
        let actionLabel = 'Assign';
        let subtext = d.vendor || 'Unknown Vendor';
        
        if (assignedWS) {
            actionLabel = 'Reassign';
            subtext = `${subtext} • Currently in ${assignedWS}`;
        }

        return `
            <div class="device-select-item" onclick="addDeviceToWorkspace(${d.id})">
                <div class="device-select-info">
                    <span class="device-select-host">${d.hostname || 'Unknown Host'}</span>
                    <span class="device-select-ip">${d.ip} • ${subtext}</span>
                </div>
                <span class="device-select-action">${actionLabel}</span>
            </div>
        `;
    }).join('');
}

async function addDeviceToWorkspace(deviceId) {
    if (!activeWorkspaceId) return;

    const device = devicesState.find(d => d.id === deviceId);
    if (!device) return;

    const currentWorkspace = workspacesState.find(w => w.id === activeWorkspaceId);
    const wsName = currentWorkspace ? currentWorkspace.name : 'this workspace';

    // Check if the device is currently in another workspace
    let otherWorkspaceName = null;
    workspacesState.forEach(ws => {
        if (ws.id !== activeWorkspaceId) {
            if ((ws.devices || []).some(d => d.id === deviceId)) {
                
                otherWorkspaceName = ws.name;
            }
        }
    });

    let confirmMsg = `Are you sure you want to add '${device.hostname || device.ip}' to workspace '${wsName}'?`;
    
    if (otherWorkspaceName) {
        confirmMsg = `Warning: '${device.hostname || device.ip}' is currently assigned to '${otherWorkspaceName}'.\n\nAre you sure you want to move it to '${wsName}'?`;
    } else if (!device.is_trusted) {
        confirmMsg = `Warning: '${device.hostname || device.ip}' is an UNTRUSTED/PENDING device.\n\nAre you sure you want to add it to '${wsName}'?`;
    }

    if (!confirm(confirmMsg)) return;

    try {
        const response = await fetch(`/api/workspaces/${activeWorkspaceId}/add-device/${deviceId}`, {
            method: 'POST',
            headers: getAuthHeaders()
        });
        if (handleApiError(response)) return;
        if (!response.ok) throw new Error('Failed to add device');

        showToast('Device successfully assigned to workspace.');
        closeModal('modal-add-workspace-device');
        fetchWorkspaces();
        fetchAuditLogs();
    } catch (error) {
        showToast(`Failed: ${error.message}`);
    }
}

// ==========================================
// XI. Account Management (Unlock)
// ==========================================

async function unlockUser(userId) {
    try {
        const response = await fetch(`/api/users/${userId}/unlock`, {
            method: 'POST',
            headers: getAuthHeaders()
        });
        if (handleApiError(response)) return;
        if (!response.ok) throw new Error('Unlock failed');

        showToast('Account unlocked successfully.');
        fetchUsers();
        fetchAuditLogs();
    } catch (error) {
        showToast(`Failed: ${error.message}`);
    }
}

// Populate employee modal user dropdown when opening
function openModal(modalId) {
    if (modalId === 'modal-device') {
        document.getElementById('device-modal-title').innerText = 'Add Network Device';
        document.getElementById('form-device').reset();
        document.getElementById('edit-device-id').value = '';
        document.getElementById('device-ip').disabled = false;
        document.getElementById('device-type').value = 'generic';
        document.getElementById('device-dept').value = 'None';
        document.getElementById('device-trust-level').value = 'Unknown';
    } else if (modalId === 'modal-user') {
        document.getElementById('form-user').reset();
    } else if (modalId === 'modal-employee') {
        document.getElementById('form-employee').reset();
        document.getElementById('edit-employee-id').value = '';
        document.getElementById('employee-modal-title').innerText = 'Add HR Employee Profile';
        // Populate linked user dropdown
        const sel = document.getElementById('emp-user-id');
        if (sel && usersState.length > 0) {
            const opts = usersState.map(u => `<option value="${u.id}">${u.username} (${u.role})</option>`).join('');
            sel.innerHTML = `<option value="">— No linked account —</option>${opts}`;
        }
    } else if (modalId === 'modal-workspace') {
        document.getElementById('form-workspace').reset();
        document.getElementById('edit-workspace-id').value = '';
        document.getElementById('workspace-modal-title').innerText = 'Create Workspace';
    }

    document.getElementById(modalId).classList.add('active');
}

// ==========================================
// XII. Real-Time Event Stream (SSE)
// ==========================================

let eventSource = null;

function initSSE() {
    if (eventSource) {
        eventSource.close();
    }
    
    eventSource = new EventSource("/api/events/stream");
    
    eventSource.addEventListener("connected", (e) => {
        console.log("SSE Connected:", JSON.parse(e.data));
    });
    
    eventSource.addEventListener("network_alert", (e) => {
        const data = JSON.parse(e.data);
        const severity = data.severity?.toLowerCase() || 'info';
        
        const msg = `${data.title}: ${data.description}`;
        showToast(msg, 7000, severity === 'critical' ? 'critical' : (severity === 'high' ? 'error' : 'warning'));
        
        fetchWorkstations();
        fetchWorkstationAlerts();
    });

    eventSource.addEventListener("security_alert", (e) => {
        const data = JSON.parse(e.data);
        const msg = `Endpoint Threat on ${data.hostname || 'Unknown'}: ${data.title}`;
        showToast(msg, 7000, 'critical');
        fetchWorkstations();
        fetchWorkstationAlerts();
    });
    
    eventSource.onerror = (err) => {
        console.error("SSE Error:", err);
    };
}

// XIII. Actions Dropdown Helper Functions
function toggleActionsDropdown(btn, event) {
    event.stopPropagation();
    const dropdown = btn.closest('.dropdown-actions');
    const isActive = dropdown.classList.contains('active');
    
    // Close all other dropdowns
    document.querySelectorAll('.dropdown-actions').forEach(d => d.classList.remove('active'));
    
    if (!isActive) {
        dropdown.classList.add('active');
    }
}

// Close dropdowns on document click
document.addEventListener('click', () => {
    document.querySelectorAll('.dropdown-actions').forEach(d => d.classList.remove('active'));
});

// ==========================================
// XIV. Dynamic Infrastructure Tree & WebSocket
// ==========================================

let currentFilteredIp = null;
let infrastructureStatusSocket = null;

async function loadDynamicNetworkTree() {
    const container = document.getElementById("dynamic-network-tree");
    if (!container) return;

    try {
        const response = await fetch("/api/infrastructure/tree", { headers: getAuthHeaders() });
        if (!response.ok) throw new Error("Failed to fetch infrastructure tree");
        const networkData = await response.json();
        
        let htmlContent = '';
        let areaIndex = 0;

        for (const [areaName, data] of Object.entries(networkData)) {
            const treeId = `dynamic-tree-zone-${areaIndex}`;
            
            // Render zone wrapper
            htmlContent += `
                <div class="tree-zone-wrapper">
                    <!-- Collapsible Zone Trigger -->
                    <button onclick="toggleTree('${treeId}', this)" class="tree-zone-toggle">
                        <i data-lucide="chevron-down" class="tree-zone-chevron"></i>
                        <i data-lucide="folder" class="tree-zone-folder"></i>
                        <span>${areaName}</span>
                    </button>

                    <!-- Tree Content Trunk -->
                    <div id="${treeId}" class="tree-trunk-container">
                        
                        <!-- Root Server Node -->
                        <div class="tree-root-node">
                            <div class="tree-root-icon">
                                <i data-lucide="server"></i>
                            </div>
                            <div class="tree-root-details">
                                <p>${data.root_server.name}</p>
                                <span>${data.root_server.ip}</span>
                            </div>
                        </div>

                        <!-- Branches Container -->
                        <div class="tree-branches-container">
            `;

            // Render endpoints
            data.endpoints.forEach(endpoint => {
                const isRouter = endpoint.type === 'router';
                const itemIconColor = isRouter ? 'bg-amber' : 'bg-blue';
                const typeIcon = isRouter ? 'wifi' : 'monitor';
                
                htmlContent += `
                    <div onclick="filterTableByDevice('${endpoint.ip}', this)" 
                         class="tree-node-item" 
                         data-node-ip="${endpoint.ip}">
                        
                        <span class="tree-connector-line"></span>
                        
                        <div class="tree-node-left">
                            <div class="node-icon-bg ${itemIconColor}">
                                <span class="node-status-dot online"></span>
                                <i data-lucide="${typeIcon}"></i>
                            </div>
                            <div class="node-details">
                                <p class="target-hostname-label">${endpoint.name}</p>
                                <span>${endpoint.ip}</span>
                            </div>
                        </div>
                        
                        <span class="traffic-tag hidden">0 Kbps</span>
                    </div>
                `;
            });

            htmlContent += `
                        </div> <!-- End Branches Container -->
                    </div> <!-- End Tree Content Trunk -->
                </div>
            `;
            areaIndex++;
        }

        container.innerHTML = htmlContent;
        lucide.createIcons();
    } catch (error) {
        console.error("Failed to map dynamic network tree:", error);
    }
}

function toggleTree(treeId, btn) {
    const container = document.getElementById(treeId);
    if (!container) return;
    container.classList.toggle("hidden");
    btn.classList.toggle("collapsed");
}

function connectStatusWebSocket() {
    if (infrastructureStatusSocket && (infrastructureStatusSocket.readyState === WebSocket.OPEN || infrastructureStatusSocket.readyState === WebSocket.CONNECTING)) {
        return;
    }
    
    const wsProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const socketUrl = `${wsProtocol}//${window.location.host}/ws/infrastructure/status`;
    
    infrastructureStatusSocket = new WebSocket(socketUrl);

    infrastructureStatusSocket.onmessage = (event) => {
        const data = JSON.parse(event.data);
        
        const targetNode = document.querySelector(`[data-node-ip="${data.target_ip}"]`);
        if (!targetNode) return;

        const badge = targetNode.querySelector('.node-status-dot');
        const trafficTag = targetNode.querySelector('.traffic-tag');

        if (data.status === 'offline') {
            if (badge) {
                badge.className = "node-status-dot offline";
            }
            if (trafficTag) {
                trafficTag.classList.add('hidden');
                trafficTag.classList.remove('alert-tag');
            }
        } 
        else if (data.status === 'high-traffic') {
            if (badge) {
                badge.className = "node-status-dot high-traffic";
            }
            if (trafficTag) {
                trafficTag.innerText = data.traffic_rate;
                trafficTag.classList.remove('hidden');
                trafficTag.classList.add('alert-tag');
            }
        } 
        else { // 'online'
            if (badge) {
                badge.className = "node-status-dot online";
            }
            if (trafficTag) {
                trafficTag.classList.add('hidden');
                trafficTag.classList.remove('alert-tag');
            }
        }
    };

    infrastructureStatusSocket.onclose = () => {
        // Retry connection after 5 seconds
        setTimeout(connectStatusWebSocket, 5000);
    };
    
    infrastructureStatusSocket.onerror = (error) => {
        console.error("Infrastructure status WebSocket error:", error);
    };
}

function filterTableByDevice(ipAddress, element) {
    const tableBody = document.getElementById("devices-list-body");
    if (!tableBody) return;

    const rows = tableBody.querySelectorAll("tr[data-device-ip]");
    const allTreeNodes = document.querySelectorAll(".tree-node-item");

    // Remove active styles from other tree nodes
    allTreeNodes.forEach(node => {
        node.classList.remove("active-filter");
    });

    if (currentFilteredIp === ipAddress) {
        currentFilteredIp = null;
        rows.forEach(row => {
            row.style.display = "";
            row.classList.remove("hidden");
        });
        return;
    }

    currentFilteredIp = ipAddress;
    element.classList.add("active-filter");

    rows.forEach(row => {
        const rowIp = row.getAttribute("data-device-ip");
        if (rowIp === ipAddress) {
            row.style.display = "";
            row.classList.remove("hidden");
        } else {
            row.style.display = "none";
            row.classList.add("hidden");
        }
    });
}

function handleGlobalSearch(query) {
    const cleanQuery = query.toLowerCase().trim();

    // 1. Filter Devices Table Rows
    const tableBody = document.getElementById("devices-list-body");
    if (tableBody) {
        const tableRows = tableBody.querySelectorAll("tr[data-device-ip]");
        tableRows.forEach(row => {
            const rowContent = row.textContent.toLowerCase();
            if (rowContent.includes(cleanQuery)) {
                row.style.display = "";
                row.classList.remove("hidden");
            } else {
                row.style.display = "none";
                row.classList.add("hidden");
            }
        });
    }

    // 2. Filter Sidebar Infrastructure Nodes
    const treeNodes = document.querySelectorAll(".tree-node-item");
    treeNodes.forEach(node => {
        const nodeIp = node.getAttribute("data-node-ip") || "";
        const hostnameLabel = node.querySelector(".target-hostname-label");
        const nodeHostname = hostnameLabel ? hostnameLabel.textContent.toLowerCase() : "";

        if (nodeIp.includes(cleanQuery) || nodeHostname.includes(cleanQuery)) {
            node.classList.remove("opacity-25", "pointer-events-none");
        } else {
            node.classList.add("opacity-25", "pointer-events-none");
        }
    });

    // 3. Expand parent blocks if search matches child nodes
    const areaContainers = document.querySelectorAll(".tree-trunk-container");
    areaContainers.forEach(container => {
        const activeChildren = container.querySelectorAll(".tree-node-item:not(.opacity-25)");
        
        if (activeChildren.length > 0 && cleanQuery !== "") {
            container.classList.remove("hidden");
            const toggleButton = container.previousElementSibling;
            if (toggleButton) {
                toggleButton.classList.remove("collapsed");
            }
        }
    });
}

function exportVisibleTableToCSV() {
    const table = document.querySelector(".data-table");
    if (!table) return;

    const rows = table.querySelectorAll("tr");
    const csvData = [];

    // Extract Headers
    const headerCells = rows[0].querySelectorAll("th");
    const headers = [];
    headerCells.forEach(cell => {
        // Strip icon sorting arrow text
        let headerText = cell.textContent.trim().replace(/↕/g, '').trim();
        headers.push(`"${headerText.replace(/"/g, '""')}"`);
    });
    if (headers.length > 0) csvData.push(headers.join(","));

    // Extract Visible Rows
    for (let i = 1; i < rows.length; i++) {
        const row = rows[i];
        if (row.classList.contains("hidden") || row.style.display === "none") continue;

        const cells = row.querySelectorAll("td");
        const rowData = [];

        cells.forEach(cell => {
            let cellText = cell.textContent.trim()
                               .replace(/\s+/g, ' ')
                               .replace(/"/g, '""');
            rowData.push(`"${cellText}"`);
        });

        if (rowData.length > 0) {
            csvData.push(rowData.join(","));
        }
    }

    const csvString = csvData.join("\n");
    const blob = new Blob([csvString], { type: "text/csv;charset=utf-8;" });
    const link = document.createElement("a");
    
    if (link.download !== undefined) {
        const url = URL.createObjectURL(blob);
        link.setAttribute("href", url);
        link.setAttribute("download", "recon_nds_device_logs.csv");
        link.style.visibility = "hidden";
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    }
}


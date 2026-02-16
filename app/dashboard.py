#/app/dashboard.py
"""
V2 Metrics dashboard for 12-category snapshot system.
Tracks file categorization, parser usage, and exports logs.
"""

from flask import Flask, render_template_string, jsonify, send_file, request
from pathlib import Path
from datetime import datetime
import json

from app.main import startup, get_metrics
from app.config.settings import get_settings

app = Flask(__name__)

# Initialize tool on startup
startup()

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>SNAP Metrics Dashboard</title>
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }
        h1 { color: #333; margin-bottom: 5px; }
        h2 { margin-top: 0; }
        .version { color: #666; font-size: 14px; margin-bottom: 20px; }
        .metric-card {
            background: white;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .metric-value {
            font-size: 48px;
            font-weight: bold;
            color: #4CAF50;
        }
        .metric-label {
            font-size: 14px;
            color: #666;
            text-transform: uppercase;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
        }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f8f8; font-weight: bold; }
        .btn {
            background: #4CAF50;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            margin-right: 10px;
        }
        .btn:hover { background: #45a049; }
        .btn-secondary { background: #2196F3; }
        .btn-secondary:hover { background: #0b7dda; }
        .timestamp { color: #999; font-size: 12px; }
        .status-normal { color: #4CAF50; }
        .status-large { color: #FF9800; }
        .status-potential-god { color: #FF5722; }
        .status-rejected { color: #F44336; font-weight: bold; }
        .search-box {
            padding: 10px;
            width: 300px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
            margin-bottom: 15px;
        }
        .log-entry {
            padding: 8px 12px;
            border-bottom: 1px solid #eee;
            font-family: monospace;
            font-size: 13px;
        }
        .log-entry:hover { background: #f9f9f9; }
        .log-info { color: #2196F3; }
        .log-warning { color: #FF9800; }
        .log-error { color: #F44336; }
        .log-debug { color: #9E9E9E; }
        .logs-container {
            max-height: 400px;
            overflow-y: auto;
            border: 1px solid #ddd;
            border-radius: 4px;
            background: #fafafa;
        }
        .tab-container { margin-bottom: 20px; }
        .tab {
            display: inline-block;
            padding: 10px 20px;
            cursor: pointer;
            border-bottom: 3px solid transparent;
            color: #666;
        }
        .tab:hover { color: #333; }
        .tab.active { border-bottom-color: #4CAF50; color: #333; font-weight: bold; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .highlight { background: #fff3cd; }
        .project-row { cursor: pointer; }
        .project-row:hover { background: #f0f0f0; }
        .project-details {
            display: none;
            background: #f9f9f9;
            padding: 15px;
            border-left: 3px solid #4CAF50;
        }
        .project-details.show { display: table-row; }
        .detail-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 10px;
        }
        .detail-item { text-align: center; }
        .detail-value { font-size: 24px; font-weight: bold; color: #4CAF50; }
        .detail-label { font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <h1>SNAP Dashboard</h1>
    <div class="version">Version 2.0 - 12 Snapshot Categories</div>

    <div style="margin-bottom: 20px;">
        <button class="btn" onclick="location.reload()">Refresh</button>
        <button class="btn btn-secondary" onclick="downloadLogs()">Export Logs</button>
    </div>

    <p class="timestamp">Last updated: <span id="timestamp"></span></p>

    <div class="grid">
        <div class="metric-card">
            <div class="metric-label">Total Projects</div>
            <div class="metric-value" id="total-projects">-</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Files Processed</div>
            <div class="metric-value" id="files-processed">-</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Snapshots Created</div>
            <div class="metric-value" id="snapshots-created">-</div>
        </div>
        <div class="metric-card">
            <div class="metric-label">Snapshots Failed</div>
            <div class="metric-value" id="snapshots-failed" style="color: #FF5722;">-</div>
        </div>
    </div>

    <div class="tab-container">
        <span class="tab active" onclick="showTab('overview')">Overview</span>
        <span class="tab" onclick="showTab('projects')">Projects</span>
        <span class="tab" onclick="showTab('logs')">Logs</span>
    </div>

    <div id="overview-tab" class="tab-content active">
        <div class="metric-card">
            <h2>File Categorization</h2>
            <table>
                <thead><tr><th>Category</th><th>LOC Range</th><th>Count</th><th>Status</th></tr></thead>
                <tbody id="categorization-table"></tbody>
            </table>
        </div>

        <div class="metric-card">
            <h2>Snapshots by Type</h2>
            <table>
                <thead><tr><th>Snapshot Type</th><th>Count</th><th>Parser</th></tr></thead>
                <tbody id="snapshot-types-table"></tbody>
            </table>
        </div>

        <div class="metric-card">
            <h2>Parser Usage</h2>
            <table>
                <thead><tr><th>Parser</th><th>Files Processed</th></tr></thead>
                <tbody id="parser-table"></tbody>
            </table>
        </div>
    </div>

    <div id="projects-tab" class="tab-content">
        <div class="metric-card">
            <h2>Projects</h2>
            <input type="text" class="search-box" id="project-search" placeholder="Search projects..." oninput="filterProjects()">
            <table>
                <thead><tr><th>Project ID</th><th>Snapshots</th><th>Files</th><th>Normal</th><th>Large</th><th>God</th><th>Rejected</th></tr></thead>
                <tbody id="project-table"></tbody>
            </table>
        </div>
    </div>

    <div id="logs-tab" class="tab-content">
        <div class="metric-card">
            <h2>Recent Logs</h2>
            <input type="text" class="search-box" id="log-search" placeholder="Filter logs..." oninput="filterLogs()">
            <select id="log-level" onchange="loadLogs()" style="padding: 10px; margin-left: 10px;">
                <option value="all">All Levels</option>
                <option value="ERROR">Errors Only</option>
                <option value="WARNING">Warnings+</option>
                <option value="INFO">Info+</option>
                <option value="DEBUG">Debug+</option>
            </select>
            <div class="logs-container" id="logs-container">
                <div class="log-entry">Loading logs...</div>
            </div>
        </div>
    </div>

    <script>
        const PARSERS = {
            file_metadata: 'tree_sitter', imports: 'tree_sitter', exports: 'tree_sitter',
            functions: 'tree_sitter', classes: 'tree_sitter', connections: 'tree_sitter',
            repo_metadata: 'tree_sitter', security: 'semgrep', quality: 'semgrep',
            doc_metadata: 'text_extractor', doc_content: 'text_extractor', doc_analysis: 'text_extractor'
        };

        let allProjects = [];
        let allLogs = [];

        function showTab(tabName) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            document.querySelector(`.tab[onclick="showTab('${tabName}')"]`).classList.add('active');
            document.getElementById(tabName + '-tab').classList.add('active');
            if (tabName === 'logs') loadLogs();
        }

        async function loadMetrics() {
            const data = await fetch('/api/metrics').then(r => r.json());

            document.getElementById('total-projects').textContent = data.projects.total || 0;
            document.getElementById('files-processed').textContent = data.files.processed || 0;
            document.getElementById('snapshots-created').textContent = data.snapshots.created || 0;
            document.getElementById('snapshots-failed').textContent = data.snapshots.failed || 0;
            document.getElementById('timestamp').textContent = new Date(data.timestamp).toLocaleString();

            const catTable = document.getElementById('categorization-table');
            catTable.innerHTML = '';
            [
                { name: 'normal', range: '< 1,500', count: data.files.categorization?.normal || 0, status: 'normal' },
                { name: 'large', range: '1,500-3,999', count: data.files.categorization?.large || 0, status: 'large' },
                { name: 'potential_god', range: '4,000-4,999', count: data.files.categorization?.potential_god || 0, status: 'potential-god' },
                { name: 'rejected', range: '>= 5,000', count: data.files.categorization?.rejected || 0, status: 'rejected' }
            ].forEach(cat => {
                const row = catTable.insertRow();
                row.insertCell(0).textContent = cat.name;
                row.insertCell(1).textContent = cat.range;
                row.insertCell(2).textContent = cat.count;
                const cell = row.insertCell(3);
                cell.textContent = cat.count > 0 ? 'Active' : '-';
                cell.className = 'status-' + cat.status;
            });

            const typesTable = document.getElementById('snapshot-types-table');
            typesTable.innerHTML = '';
            if (data.snapshots.by_type) {
                for (const [type, count] of Object.entries(data.snapshots.by_type)) {
                    const row = typesTable.insertRow();
                    row.insertCell(0).textContent = type;
                    row.insertCell(1).textContent = count;
                    row.insertCell(2).textContent = PARSERS[type] || 'unknown';
                }
            }

            const parserTable = document.getElementById('parser-table');
            parserTable.innerHTML = '';
            if (data.parsers) {
                for (const [parser, count] of Object.entries(data.parsers)) {
                    const row = parserTable.insertRow();
                    row.insertCell(0).textContent = parser;
                    row.insertCell(1).textContent = count;
                }
            }

            allProjects = data.projects.list || [];
            renderProjects(allProjects);
        }

        function renderProjects(projects) {
            const projectTable = document.getElementById('project-table');
            projectTable.innerHTML = '';
            projects.forEach(project => {
                const row = projectTable.insertRow();
                row.className = 'project-row';
                row.insertCell(0).textContent = project.project_id;
                row.insertCell(1).textContent = project.snapshots;
                row.insertCell(2).textContent = project.files || '-';
                row.insertCell(3).textContent = project.categorization?.normal || '-';
                row.insertCell(4).textContent = project.categorization?.large || '-';
                row.insertCell(5).textContent = project.categorization?.potential_god || '-';
                row.insertCell(6).textContent = project.categorization?.rejected || '-';
            });
        }

        function filterProjects() {
            const query = document.getElementById('project-search').value.toLowerCase();
            const filtered = allProjects.filter(p => p.project_id.toLowerCase().includes(query));
            renderProjects(filtered);
        }

        async function loadLogs() {
            const level = document.getElementById('log-level').value;
            const data = await fetch('/api/logs?level=' + level + '&limit=100').then(r => r.json());
            allLogs = data.logs || [];
            renderLogs(allLogs);
        }

        function renderLogs(logs) {
            const container = document.getElementById('logs-container');
            if (!logs.length) {
                container.innerHTML = '<div class="log-entry">No logs found</div>';
                return;
            }
            container.innerHTML = logs.map(log => {
                const levelClass = 'log-' + (log.level || 'info').toLowerCase();
                const time = log.timestamp ? new Date(log.timestamp).toLocaleString() : '';
                return `<div class="log-entry ${levelClass}">[${time}] [${log.level || 'INFO'}] ${log.message || log.msg || JSON.stringify(log)}</div>`;
            }).join('');
        }

        function filterLogs() {
            const query = document.getElementById('log-search').value.toLowerCase();
            const filtered = allLogs.filter(log => {
                const text = (log.message || log.msg || JSON.stringify(log)).toLowerCase();
                return text.includes(query);
            });
            renderLogs(filtered);
        }

        function downloadLogs() {
            window.location.href = '/api/logs/export';
        }

        loadMetrics();
        setInterval(loadMetrics, 30000);
    </script>
</body>
</html>
"""

@app.route('/')
def dashboard():
    return render_template_string(DASHBOARD_HTML)

@app.route('/api/metrics')
def api_metrics():
    metrics = get_metrics()
    metrics['timestamp'] = datetime.utcnow().isoformat() + 'Z'

    # Add per-project categorization data
    settings = get_settings()
    projects_dir = settings.data_dir / "projects"

    for project in metrics.get('projects', {}).get('list', []):
        project_id = project.get('project_id', '')
        # Find manifest
        for manifest_path in projects_dir.glob("**/project_manifest.json"):
            try:
                with open(manifest_path) as f:
                    manifest = json.load(f)
                if manifest.get('project_id') == project_id:
                    stats = manifest.get('stats', {})
                    project['categorization'] = stats.get('file_categorization', {})
                    break
            except:
                pass

    return jsonify(metrics)

@app.route('/api/logs')
def api_logs():
    """Get recent logs from log files."""
    level = request.args.get('level', 'all')
    limit = int(request.args.get('limit', 100))

    settings = get_settings()
    logs = []

    # Read from data/logs if exists
    logs_dir = settings.data_dir / "logs"
    log_file = logs_dir / "app.log"

    if log_file.exists():
        try:
            with open(log_file, 'r') as f:
                lines = f.readlines()[-limit:]
                for line in lines:
                    try:
                        log_entry = json.loads(line.strip())
                        logs.append(log_entry)
                    except json.JSONDecodeError:
                        # Plain text log
                        logs.append({'message': line.strip(), 'level': 'INFO'})
        except:
            pass

    # Also check snapshot_logs.json
    snapshot_log = logs_dir / "snapshot_logs.json"
    if snapshot_log.exists():
        try:
            with open(snapshot_log) as f:
                snapshot_logs = json.load(f)
                if isinstance(snapshot_logs, list):
                    logs.extend(snapshot_logs[-limit:])
        except:
            pass

    # Filter by level
    level_order = {'DEBUG': 0, 'INFO': 1, 'WARNING': 2, 'ERROR': 3}
    if level != 'all' and level in level_order:
        min_level = level_order[level]
        logs = [l for l in logs if level_order.get(l.get('level', 'INFO'), 1) >= min_level]

    return jsonify({'logs': logs[-limit:]})

@app.route('/api/logs/export')
def export_logs():
    settings = get_settings()
    logs_dir = settings.data_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_file = logs_dir / "snapshot_logs.json"

    if not log_file.exists():
        with open(log_file, 'w') as f:
            json.dump([], f)

    return send_file(
        log_file,
        mimetype='application/json',
        as_attachment=True,
        download_name=f'snapshot_logs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    )

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)

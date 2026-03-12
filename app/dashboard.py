# app/dashboard.py
"""
Admin dashboard for SNAP. All admin commands exposed as web UI.
Run with: python -m app.dashboard
"""

from collections import Counter
from datetime import datetime
from pathlib import Path
import json
import os
import shutil
import sys

import threading

from flask import Flask, Response, jsonify, request, send_file
from sqlalchemy import text

from app.config.settings import get_settings
from app.storage.db import db_session
from app.storage.snapshot_repo import SnapshotRepository

app = Flask(__name__)

# Generic request handler
def handle_request(func):
    """DRY wrapper for repo method calls with error handling."""
    try:
        result = func()
        return jsonify(result) if not isinstance(result, Response) else result
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

# ── In-process ingest watcher tracking ────────────────────────────────────────
_ingest_lock = threading.Lock()
_ingest_started = False
_startup_error: str = ""


def _derive_project_id(repo_url):
    name = repo_url.rstrip("/").split("/")[-1]
    if name.endswith(".git"):
        name = name[:-4]
    name = name.lower().replace("-", "_")
    if len(name) < 3:
        name = name + "_" * (3 - len(name))
    return name


def _rmtree(path):
    if not path.exists():
        return
    def _on_err(fn, p, _):
        try:
            os.chmod(p, 0o777)
            fn(p)
        except Exception:
            pass
    kw = {"onexc": _on_err} if sys.version_info >= (3, 12) else {"onerror": _on_err}
    shutil.rmtree(str(path), **kw)


# ── API ───────────────────────────────────────────────────────────────────────

@app.route("/api/projects")
def api_projects():
    try:
        with db_session() as s:
            pids = s.execute(text(
                "SELECT DISTINCT project_id FROM project_runs ORDER BY project_id"
            )).fetchall()
            active = s.execute(text(
                "SELECT par.project_id, SUM(pr.snapshot_count), SUM(pr.file_count)"
                " FROM project_active_runs par"
                " JOIN project_runs pr ON par.active_run_id = pr.run_id"
                " GROUP BY par.project_id"
            )).fetchall()
        am = {r[0]: {"snapshots": int(r[1] or 0), "files": int(r[2] or 0)} for r in active}
        return jsonify({"projects": [
            {"project_id": p[0],
             "snapshots": am.get(p[0], {}).get("snapshots", 0),
             "files":     am.get(p[0], {}).get("files", 0)}
            for p in pids
        ]})
    except Exception as exc:
        return jsonify({"error": str(exc), "projects": []}), 500


@app.route("/api/projects/<pid>/runs")
def api_runs(pid):
    try:
        with db_session() as s:
            rows = s.execute(text(
                "SELECT run_id, ingest_source, source_ref, status,"
                " created_at, completed_at, snapshot_count, file_count"
                " FROM project_runs WHERE project_id = :p ORDER BY created_at DESC"
            ), {"p": pid}).fetchall()
        return jsonify([{
            "run_id": r[0], "ingest_source": r[1], "source_ref": r[2], "status": r[3],
            "created_at":   (r[4] if isinstance(r[4], str) else r[4].isoformat()) if r[4] else None,
            "completed_at": (r[5] if isinstance(r[5], str) else r[5].isoformat()) if r[5] else None,
            "snapshot_count": r[6] or 0, "file_count": r[7] or 0,
        } for r in rows])
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/projects/<pid>/manifest")
def api_manifest(pid):
    try:
        with db_session() as s:
            runs = s.execute(text(
                "SELECT run_id, ingest_source, status, snapshot_count, file_count"
                " FROM project_runs WHERE project_id = :p ORDER BY created_at DESC"
            ), {"p": pid}).fetchall()
            active = s.execute(text(
                "SELECT par.ingest_source, pr.run_id, pr.source_ref,"
                " pr.snapshot_count, pr.file_count, pr.completed_at"
                " FROM project_active_runs par"
                " JOIN project_runs pr ON par.active_run_id = pr.run_id"
                " WHERE par.project_id = :p"
            ), {"p": pid}).fetchall()
        issues = []
        for r in runs:
            if r[2] == "failed":
                issues.append("FAILED run: %s (%s)" % (r[0], r[1]))
            if r[2] == "draft":
                issues.append("DRAFT run (not promoted): %s (%s)" % (r[0], r[1]))
            if r[2] == "active" and (r[3] or 0) == 0:
                issues.append("Active run has 0 snapshots: %s" % r[0])
            if r[2] == "active" and (r[4] or 0) == 0:
                issues.append("Active run has 0 files: %s" % r[0])
        return jsonify({
            "health": {"ok": len(issues) == 0, "issues": issues},
            "run_history": {
                "total": len(runs),
                "by_status": dict(Counter(r[2] for r in runs)),
            },
            "active_sources": [{
                "ingest_source": r[0],
                "run_id": r[1],
                "source_ref": r[2],
                "snapshot_count": r[3] or 0,
                "file_count": r[4] or 0,
                "completed_at": (r[5] if isinstance(r[5], str) else r[5].isoformat()) if r[5] else None,
            } for r in active],
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/projects/<pid>/snapshots")
def api_snapshots(pid):
    try:
        snap_type = request.args.get("type")
        file_frag = request.args.get("file")
        status_filter = request.args.get("status", "active")
        limit = int(request.args.get("limit", 50))
        with db_session() as s:
            if status_filter == "all":
                run_ids = [r[0] for r in s.execute(text(
                    "SELECT run_id FROM project_runs WHERE project_id = :p"
                ), {"p": pid}).fetchall()]
            elif status_filter == "active":
                run_ids = [r[0] for r in s.execute(text(
                    "SELECT active_run_id FROM project_active_runs WHERE project_id = :p"
                ), {"p": pid}).fetchall()]
            else:
                run_ids = [r[0] for r in s.execute(text(
                    "SELECT run_id FROM project_runs WHERE project_id = :p AND status = :st"
                ), {"p": pid, "st": status_filter}).fetchall()]
            if not run_ids:
                return jsonify({"total": 0, "files": 0, "by_type": {}, "records": []})
            _in = ",".join(f":rid{i}" for i in range(len(run_ids)))
            where = f"WHERE run_id IN ({_in})"
            params: dict = {f"rid{i}": v for i, v in enumerate(run_ids)}
            if snap_type:
                where += " AND snapshot_type = :st"
                params["st"] = snap_type
            if file_frag:
                where += " AND source_file LIKE :ff"
                params["ff"] = "%" + file_frag + "%"
            rows = s.execute(text(
                "SELECT snapshot_id, snapshot_type, source_file, source_hash, content_hash, simhash, "
                "LENGTH(minhash) as minhash_len, created_at"
                " FROM snapshot_notebooks %s ORDER BY source_file, snapshot_type LIMIT :lim" % where
            ), {**params, "lim": limit}).fetchall()
        by_type = dict(Counter(r[1] for r in rows))
        records = [{
            "snapshot_id": r[0], "snapshot_type": r[1], "source_file": r[2],
            "source_hash": r[3], "content_hash": r[4], "simhash": r[5],
            "minhash_len": r[6], "created_at": (r[7] if isinstance(r[7], str) else r[7].isoformat()) if r[7] else None
        } for r in rows]
        return jsonify({
            "total": len(rows), "files": len(set(r[2] for r in rows)),
            "by_type": by_type, "records": records,
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/snapshots/<snapshot_id>")
def api_snapshot_detail(snapshot_id):
    try:
        with db_session() as s:
            row = s.execute(text(
                "SELECT snapshot_type, source_file, binary_data, run_id, project_id,"
                "       source_hash, content_hash, simhash, created_at"
                " FROM snapshot_notebooks WHERE snapshot_id = :sid"
            ), {"sid": snapshot_id}).fetchone()
        if not row:
            return jsonify({"error": "Snapshot not found"}), 404
        field_values = {}
        try:
            repo = SnapshotRepository()
            field_values = repo._unpacker.unpack(bytes(row[2]))["field_values"]
        except Exception as e:
            field_values = {"unpack_error": str(e)}
        return jsonify({
            "snapshot_id": snapshot_id,
            "snapshot_type": row[0],
            "source_file": row[1],
            "field_values": field_values,
            "run_id": row[3],
            "project_id": row[4],
            "source_hash": row[5],
            "content_hash": row[6],
            "simhash": str(row[7]) if row[7] is not None else None,
            "created_at": (row[8] if isinstance(row[8], str) else row[8].isoformat()) if row[8] else None,
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/projects/<pid>", methods=["DELETE"])
def api_delete(pid):
    try:
        with db_session() as s:
            s.execute(text(
                "DELETE FROM snapshot_notebooks"
                " WHERE run_id IN (SELECT run_id FROM project_runs WHERE project_id = :p)"
            ), {"p": pid})
            s.execute(text("DELETE FROM project_active_runs WHERE project_id = :p"), {"p": pid})
            s.execute(text("DELETE FROM project_runs WHERE project_id = :p"), {"p": pid})
        settings = get_settings()
        for d in [
            settings.data_dir / "projects" / pid,
            settings.repos_dir / pid,
            settings.data_dir / "staging" / pid,
        ]:
            _rmtree(d)
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.route("/api/ingest/status")
def api_ingest_status():
    with _ingest_lock:
        return jsonify({"running": _ingest_started, "error": _startup_error})


@app.route("/api/ingest/start", methods=["POST"])
def api_ingest_start():
    global _ingest_started, _startup_error
    with _ingest_lock:
        if _ingest_started:
            return jsonify({"ok": False, "error": "Ingest watchers already running"}), 409
    def _do_start():
        global _ingest_started, _startup_error
        try:
            from app.main import startup
            startup()
            with _ingest_lock:
                _ingest_started = True
                _startup_error = ""
        except Exception as exc:
            with _ingest_lock:
                _startup_error = str(exc)
    threading.Thread(target=_do_start, daemon=True).start()
    return jsonify({"ok": True, "msg": "Ingest startup in progress"})


@app.route("/api/ingest/stop", methods=["POST"])
def api_ingest_stop():
    global _ingest_started
    with _ingest_lock:
        _ingest_started = False
    return jsonify({"ok": True})


@app.route("/api/clone-github", methods=["POST"])
def api_clone():
    try:
        from app.ingest.github_cloner import clone_github_repo
        body = request.get_json(force=True) or {}
        repo_url = (body.get("repo_url") or "").strip()
        if not repo_url:
            return jsonify({"ok": False, "error": "repo_url required"}), 400
        pid = _derive_project_id(repo_url)
        clone_github_repo(repo_remote=repo_url, project_id=pid)
        return jsonify({"ok": True, "project_id": pid})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.route("/api/staging/upload", methods=["POST"])
def api_stage():
    try:
        from app.ingest.local_loader import stage_directory, get_project_staging_path
        body = request.get_json(force=True) or {}
        pid = (body.get("project_id")  or "").strip()
        src = (body.get("source_path") or "").strip()
        if not pid or not src:
            return jsonify({"ok": False, "error": "project_id and source_path required"}), 400
        source = Path(src).resolve()
        if not source.exists():
            return jsonify({"ok": False, "error": "Path not found: " + src}), 400
        if source.is_file():
            staging = get_project_staging_path(pid)
            staging.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, staging / source.name)
            count = 1
        else:
            count = stage_directory(source, pid)
        return jsonify({"ok": True, "files_staged": count})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.route("/api/logs")
def api_logs():
    try:
        level = request.args.get("level", "all")
        limit = int(request.args.get("limit", 300))
        settings = get_settings()
        log_root = settings.data_dir / "logs"
        log_file = log_root / "app_debug.log"
        if not log_file.exists():
            log_file = log_root / "app.log"
        logs = []
        if log_file.exists():
            with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()[-(limit * 3):]
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    logs.append(json.loads(line))
                except json.JSONDecodeError:
                    logs.append({"message": line, "level": "INFO"})
        level_order = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3}
        if level != "all" and level in level_order:
            ml = level_order[level]
            logs = [lg for lg in logs
                    if level_order.get((lg.get("level") or "INFO").upper(), 1) >= ml]
        return jsonify({"logs": logs[-limit:]})
    except Exception as exc:
        return jsonify({"error": str(exc), "logs": []}), 500


@app.route("/api/logs/export")
def api_logs_export():
    settings = get_settings()
    log_root = settings.data_dir / "logs"
    log_file = log_root / "app_debug.log"
    if not log_file.exists():
        log_file = log_root / "app.log"
    if not log_file.exists():
        log_file.parent.mkdir(parents=True, exist_ok=True)
        log_file.write_text("")
    return send_file(
        log_file, mimetype="text/plain", as_attachment=True,
        download_name="snap_logs_%s.log" % datetime.now().strftime("%Y%m%d_%H%M%S"),
    )


# ── CRUD+Rebase endpoints ──

@app.route("/api/snapshots/<snapshot_id>", methods=["PATCH"])
def update_snapshot_endpoint(snapshot_id):
    return handle_request(lambda: SnapshotRepository().update_snapshot(snapshot_id, request.json))


@app.route("/api/runs/<run_id>/status", methods=["PATCH"])
def update_run_status_endpoint(run_id):
    new_status = request.json.get("status")
    if not new_status:
        return jsonify({"error": "status field required"}), 400
    try:
        with db_session() as s:
            s.execute(text(
                "UPDATE project_runs SET status = :st WHERE run_id = :rid"
            ), {"st": new_status, "rid": run_id})
            s.commit()
        return jsonify({"ok": True, "run_id": run_id, "status": new_status})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/runs/<run_id>", methods=["DELETE"])
def delete_run_endpoint(run_id):
    return handle_request(lambda: SnapshotRepository().delete_run(run_id))


@app.route("/api/snapshots/<snapshot_id>", methods=["DELETE"])
def delete_snapshot_endpoint(snapshot_id):
    return handle_request(lambda: SnapshotRepository().delete_snapshot(snapshot_id))


@app.route("/api/runs/<run_id>/promote", methods=["POST"])
def promote_run_endpoint(run_id):
    return handle_request(lambda: SnapshotRepository().promote_run(run_id))


@app.route("/api/runs/<run_id>/revalidate", methods=["POST"])
def revalidate_run_endpoint(run_id):
    return handle_request(lambda: SnapshotRepository().revalidate_run(run_id))


@app.route("/api/runs/<run_id>/validation", methods=["GET"])
def get_run_validation_endpoint(run_id):
    return handle_request(lambda: SnapshotRepository().get_run_validation(run_id))


# ── HTML built as concatenated Python strings — no triple-quote escape issues ──

def _html():
    css = (
        "<style>"
        "*{box-sizing:border-box;margin:0;padding:0}"
        "body{font-family:Arial,sans-serif;background:#f0f2f5;color:#222;padding:20px}"
        "h1{margin-bottom:20px;color:#1a1a2e}"
        "h2{font-size:17px;margin-bottom:14px;padding-bottom:8px;border-bottom:1px solid #eee}"
        "h3{font-size:14px;margin-bottom:10px}"
        ".stats{display:flex;gap:14px;margin-bottom:18px;align-items:center;flex-wrap:wrap}"
        ".card{background:#fff;border-radius:8px;padding:14px 24px;box-shadow:0 1px 3px rgba(0,0,0,.12);text-align:center;min-width:120px}"
        ".val{font-size:38px;font-weight:bold;color:#1976D2}"
        ".lbl{font-size:11px;color:#777;text-transform:uppercase;letter-spacing:1px;margin-top:2px}"
        ".tabs{display:flex;border-bottom:2px solid #ddd;margin-bottom:0}"
        ".tab{padding:10px 26px;cursor:pointer;border:none;background:none;font-size:14px;color:#666;border-bottom:3px solid transparent;margin-bottom:-2px}"
        ".tab.on{color:#1976D2;border-bottom-color:#1976D2;font-weight:bold}"
        ".tab:hover{color:#333}"
        ".pane{background:#fff;border-radius:0 0 8px 8px;padding:22px;box-shadow:0 1px 3px rgba(0,0,0,.12);min-height:280px}"
        ".row{display:flex;gap:8px;align-items:center;margin-bottom:14px;flex-wrap:wrap}"
        "input[type=text]{padding:8px 11px;border:1px solid #ccc;border-radius:4px;font-size:14px}"
        "select{padding:8px 11px;border:1px solid #ccc;border-radius:4px;font-size:14px;background:#fff}"
        ".btn{padding:7px 15px;border:none;border-radius:4px;cursor:pointer;font-size:13px;font-weight:bold}"
        ".btn:hover{opacity:.85}"
        ".blue{background:#1976D2;color:#fff}.green{background:#388E3C;color:#fff}"
        ".red{background:#D32F2F;color:#fff}.orange{background:#F57C00;color:#fff}.gray{background:#757575;color:#fff}"
        "table{width:100%;border-collapse:collapse;font-size:13px}"
        "th{background:#f5f5f5;padding:9px 11px;text-align:left;font-size:11px;text-transform:uppercase;color:#555;border-bottom:2px solid #ddd}"
        "td{padding:9px 11px;border-bottom:1px solid #eee;vertical-align:middle}"
        "tr:hover td{background:#fafafa}"
        ".det{background:#f5f8ff;border-left:4px solid #1976D2;padding:14px 18px;margin-top:14px;border-radius:0 4px 4px 0}"
        ".sec{margin-bottom:26px}"
        ".fg{margin-bottom:12px}"
        ".fg label{display:block;font-weight:bold;margin-bottom:4px;font-size:13px;color:#444}"
        ".fg input{width:400px;max-width:100%}"
        ".rb{margin-top:10px;padding:9px 13px;border-radius:4px;font-family:monospace;font-size:13px}"
        ".ok{background:#e8f5e9;color:#1b5e20;border:1px solid #a5d6a7}"
        ".err{background:#ffebee;color:#b71c1c;border:1px solid #ef9a9a}"
        ".logbox{max-height:500px;overflow-y:auto;background:#1a1a2e;border-radius:6px;padding:12px 14px;margin-top:10px}"
        ".ll{font-family:'Courier New',monospace;font-size:12px;padding:2px 0;white-space:pre-wrap;word-break:break-all;line-height:1.5}"
        ".ER{color:#ff5252}.WA{color:#ffab40}.IN{color:#69f0ae}.DB{color:#90a4ae}.DF{color:#cfd8dc}"
        ".s-active{color:#4CAF50;font-weight:bold}.s-failed{color:#f44336;font-weight:bold}"
        ".s-draft{color:#FF9800;font-weight:bold}.s-superseded{color:#9E9E9E}"
        ".hok{color:#388E3C;font-weight:bold}.hfail{color:#D32F2F;font-weight:bold}"
        ".ab{display:inline-block;padding:4px 9px;margin:2px;border:none;border-radius:3px;cursor:pointer;font-size:12px;font-weight:bold;color:#fff}"
        "</style>"
    )

    html_body = (
        "<h1>SNAP Dashboard</h1>"

        "<div class='stats'>"
        "<div class='card'><div class='val' id='sp'>-</div><div class='lbl'>Projects</div></div>"
        "<div class='card'><div class='val' id='ss'>-</div><div class='lbl'>Snapshots</div></div>"
        "<div class='card'><div class='val' id='sf'>-</div><div class='lbl'>Files</div></div>"
        "<div style='margin-left:auto;display:flex;gap:8px'>"
        "<button class='btn blue' onclick='loadProjects()'>Refresh</button>"
        "<button class='btn gray' onclick='window.location=\"/api/logs/export\"'>Export Logs</button>"
        "</div></div>"

        "<div class='tabs'>"
        "<button class='tab on' id='bt-projects' onclick='showTab(\"projects\")'>Projects</button>"
        "<button class='tab' id='bt-admin'    onclick='showTab(\"admin\")'>Admin</button>"
        "<button class='tab' id='bt-logs'     onclick='showTab(\"logs\")'>Logs</button>"
        "</div>"

        # Projects pane
        "<div id='pane-projects' class='pane'>"
        "<div class='row'>"
        "<input type='text' id='search' placeholder='Search by project ID...' style='width:280px' oninput='renderProjects()'>"
        "</div>"
        "<table><thead><tr>"
        "<th>Project ID</th><th>Snapshots</th><th>Files</th><th>Actions</th>"
        "</tr></thead>"
        "<tbody id='ptbody'><tr><td colspan='4'>Loading...</td></tr></tbody></table>"
        "<div id='det'></div>"
        "</div>"

        # Admin pane
        "<div id='pane-admin' class='pane' style='display:none'>"

        "<div class='sec'><h2>Ingest Watchers</h2>"
        "<div class='row' style='margin-bottom:10px'>"
        "<span id='ingest-dot' style='display:inline-block;width:14px;height:14px;border-radius:50%;background:#9E9E9E;margin-right:6px'></span>"
        "<span id='ingest-status-lbl' style='font-size:14px;color:#555'>Checking...</span>"
        "</div>"
        "<div class='row'>"
        "<button class='btn green' onclick='doIngestStart()'>Start Ingest</button>"
        "<button class='btn red'   onclick='doIngestStop()'>Stop Ingest</button>"
        "</div>"
        "<div id='ingest-res' class='rb' style='display:none'></div></div>"

        "<div class='sec'><h2>Clone GitHub Repository</h2>"
        "<div class='fg'><label>Repository URL</label>"
        "<input type='text' id='clone-url' placeholder='https://github.com/owner/repo'></div>"
        "<button class='btn blue' onclick='doClone()'>Clone Repository</button>"
        "<div id='clone-res' class='rb' style='display:none'></div></div>"

        "<div class='sec'><h2>Upload Local Directory to Staging</h2>"
        "<div class='fg'><label>Project ID</label>"
        "<input type='text' id='stage-pid' placeholder='my_project'></div>"
        "<div class='fg'><label>Source Path (absolute)</label>"
        "<input type='text' id='stage-path' placeholder='C:/path/to/source'></div>"
        "<button class='btn green' onclick='doStage()'>Upload to Staging</button>"
        "<div id='stage-res' class='rb' style='display:none'></div></div>"

        "<div class='sec'><h2>Delete Project</h2>"
        "<div class='fg'><label>Project ID</label>"
        "<input type='text' id='del-pid' placeholder='project_id'></div>"
        "<button class='btn red' onclick='doAdminDelete()'>Delete Project</button>"
        "<div id='del-res' class='rb' style='display:none'></div></div>"

        "<div class='sec'><h2>Query Snapshots</h2>"
        "<div class='fg'><label>Project ID</label>"
        "<input type='text' id='sq-pid' placeholder='project_id'></div>"
        "<div class='fg'><label>Snapshot Type (optional)</label>"
        "<input type='text' id='sq-type' placeholder='e.g. security_hotspots'></div>"
        "<div class='fg'><label>File Path Filter (optional)</label>"
        "<input type='text' id='sq-file' placeholder='e.g. src/auth'></div>"
        "<button class='btn orange' onclick='doQuerySnaps()'>Query Snapshots</button>"
        "<div id='sq-res' class='rb' style='display:none'></div></div>"

        "</div>"

        # Logs pane
        "<div id='pane-logs' class='pane' style='display:none'>"
        "<div class='row'>"
        "<input type='text' id='log-filter' placeholder='Filter messages...' style='width:260px' oninput='filterLogs()'>"
        "<select id='log-level' onchange='loadLogs()'>"
        "<option value='all'>All Levels</option>"
        "<option value='ERROR'>Errors Only</option>"
        "<option value='WARNING'>Warnings+</option>"
        "<option value='INFO'>Info+</option>"
        "</select>"
        "<button class='btn blue' onclick='loadLogs()'>Refresh Logs</button>"
        "</div>"
        "<div class='logbox' id='logbox'>"
        "<div class='ll DF'>Switch to Logs tab to load.</div>"
        "</div></div>"
    )

    # JavaScript — written as a plain Python string, no triple-quote, no backslash issues
    js_lines = [
        "var ALL=[],LOGS=[];",

        "function showTab(n){",
        "  ['projects','admin','logs'].forEach(function(t){",
        "    document.getElementById('pane-'+t).style.display='none';",
        "    document.getElementById('bt-'+t).className='tab';",
        "  });",
        "  document.getElementById('pane-'+n).style.display='block';",
        "  document.getElementById('bt-'+n).className='tab on';",
        "  if(n==='logs')loadLogs();",
        "}",

        "function renderProjects(){",
        "  var q=(document.getElementById('search').value||'').toLowerCase();",
        "  var list=ALL.filter(function(p){return p.project_id.toLowerCase().indexOf(q)!==-1;});",
        "  var tb=document.getElementById('ptbody');",
        "  if(!list.length){tb.innerHTML='<tr><td colspan=\"4\">No projects found.</td></tr>';return;}",
        "  var h='';",
        "  list.forEach(function(p){",
        "    h+='<tr data-pid=\"'+p.project_id+'\">';",
        "    h+='<td><strong>'+p.project_id+'</strong></td>';",
        "    h+='<td>'+(p.snapshots||0)+'</td>';",
        "    h+='<td>'+(p.files||0)+'</td>';",
        "    h+='<td>';",
        "    h+='<button class=\"ab blue\" data-action=\"runs\">Runs</button>';",
        "    h+='<button class=\"ab orange\" data-action=\"manifest\">Manifest</button>';",
        "    h+='<button class=\"ab green\" data-action=\"snaps\">Snapshots</button>';",
        "    h+='<button class=\"ab red\" data-action=\"del\">Delete</button>';",
        "    h+='</td></tr>';",
        "  });",
        "  tb.innerHTML=h;",
        "}",

        "document.addEventListener('click',function(e){",
        "  var btn=e.target.closest('[data-action]');",
        "  if(!btn)return;",
        "  var row=e.target.closest('[data-pid]');",
        "  if(!row)return;",
        "  var pid=row.getAttribute('data-pid');",
        "  var act=btn.getAttribute('data-action');",
        "  if(act==='runs')showRuns(pid);",
        "  else if(act==='manifest')showManifest(pid);",
        "  else if(act==='snaps')showSnaps(pid);",
        "  else if(act==='del')doTableDelete(pid);",
        "});",

        "function loadProjects(){",
        "  document.getElementById('ptbody').innerHTML='<tr><td colspan=\"4\">Loading...</td></tr>';",
        "  fetch('/api/projects')",
        "    .then(function(r){return r.json();})",
        "    .then(function(d){",
        "      if(d.error)throw new Error(d.error);",
        "      ALL=d.projects||[];",
        "      var sn=0,fi=0;",
        "      ALL.forEach(function(p){sn+=p.snapshots||0;fi+=p.files||0;});",
        "      document.getElementById('sp').textContent=ALL.length;",
        "      document.getElementById('ss').textContent=sn;",
        "      document.getElementById('sf').textContent=fi;",
        "      renderProjects();",
        "    })",
        "    .catch(function(e){",
        "      document.getElementById('sp').textContent='ERR';",
        "      document.getElementById('ptbody').innerHTML='<tr><td colspan=\"4\" style=\"color:#D32F2F\">'+e.message+'</td></tr>';",
        "    });",
        "}",

        "function det(h){document.getElementById('det').innerHTML='<div class=\"det\">'+h+'</div>';}",

        "function showRuns(pid){",
        "  det('<p>Loading...</p>');",
        "  fetch('/api/projects/'+encodeURIComponent(pid)+'/runs')",
        "    .then(function(r){return r.json();})",
        "    .then(function(rows){",
        "      if(rows.error){det('<p class=\"hfail\">'+rows.error+'</p>');return;}",
        "      var h='<h3>Runs: '+pid+'</h3>';",
        "      if(!rows.length){det(h+'<p>No runs.</p>');return;}",
        "      h+='<table><thead><tr><th>Run ID</th><th>Source</th><th>Status</th><th>Files</th><th>Snapshots</th><th>Created</th></tr></thead><tbody>';",
        "      rows.forEach(function(r){",
        "        var c=r.created_at?r.created_at.replace('T',' ').slice(0,19):'-';",
        "        h+='<tr><td style=\"font-family:monospace;font-size:11px\">'+r.run_id+'</td><td>'+(r.ingest_source||'-')+'</td><td class=\"s-'+r.status+'\">'+r.status+'</td><td>'+(r.file_count||0)+'</td><td>'+(r.snapshot_count||0)+'</td><td>'+c+'</td></tr>';",
        "      });",
        "      det(h+'</tbody></table>');",
        "    })",
        "    .catch(function(e){det('<p class=\"hfail\">'+e.message+'</p>');});",
        "}",

        "function showManifest(pid){",
        "  det('<p>Loading...</p>');",
        "  fetch('/api/projects/'+encodeURIComponent(pid)+'/manifest')",
        "    .then(function(r){return r.json();})",
        "    .then(function(d){",
        "      if(d.error){det('<p class=\"hfail\">'+d.error+'</p>');return;}",
        "      var h='<h3>Manifest: '+pid+'</h3>';",
        "      if(d.health.ok){h+='<p class=\"hok\">Health: OK</p>';}",
        "      else{h+='<p class=\"hfail\">Issues:</p><ul>';d.health.issues.forEach(function(i){h+='<li>'+i+'</li>';});h+='</ul>';}",
        "      h+='<p style=\"margin-top:8px\">Run history: '+d.run_history.total+' total</p><ul>';",
        "      Object.keys(d.run_history.by_status||{}).forEach(function(k){h+='<li class=\"s-'+k+'\">'+k+': '+d.run_history.by_status[k]+'</li>';});",
        "      h+='</ul>';",
        "      if(d.active_sources&&d.active_sources.length){",
        "        h+='<h3 style=\"margin-top:10px\">Active Sources</h3><table><thead><tr><th>Source</th><th>Files</th><th>Snapshots</th><th>Completed</th></tr></thead><tbody>';",
        "        d.active_sources.forEach(function(s){",
        "          var co=s.completed_at?s.completed_at.replace('T',' ').slice(0,19):'in-progress';",
        "          h+='<tr><td>'+s.ingest_source+'</td><td>'+s.file_count+'</td><td>'+s.snapshot_count+'</td><td>'+co+'</td></tr>';",
        "        });",
        "        h+='</tbody></table>';",
        "      }",
        "      det(h);",
        "    })",
        "    .catch(function(e){det('<p class=\"hfail\">'+e.message+'</p>');});",
        "}",

        "function showSnaps(pid){",
        "  det('<p>Loading...</p>');",
        "  fetch('/api/projects/'+encodeURIComponent(pid)+'/snapshots?limit=200')",
        "    .then(function(r){return r.json();})",
        "    .then(function(d){",
        "      if(d.error){det('<p class=\"hfail\">'+d.error+'</p>');return;}",
        "      var h='<h3>Snapshots: '+pid+'</h3><p style=\"margin-bottom:10px\">'+d.total+' snapshots across '+d.files+' files</p>';",
        "      if(!d.total){det(h+'<p>No snapshots in active runs.</p>');return;}",
        "      h+='<table style=\"width:auto;margin-bottom:14px\"><thead><tr><th>Type</th><th>Count</th></tr></thead><tbody>';",
        "      Object.keys(d.by_type||{}).sort().forEach(function(k){h+='<tr><td>'+k+'</td><td>'+d.by_type[k]+'</td></tr>';});",
        "      h+='</tbody></table>';",
        "      if(d.records&&d.records.length){",
        "        h+='<table><thead><tr><th>ID</th><th>Type</th><th>File</th><th>Created</th></tr></thead><tbody>';",
        "        d.records.forEach(function(r){",
        "          var c=r.created_at?r.created_at.replace('T',' ').slice(0,19):'-';",
        "          h+='<tr>';",
        "          h+='<td><a href=\"#\" class=\"snap-det-link\" data-sid=\"'+r.snapshot_id+'\" style=\"font-family:monospace;font-size:11px;color:#1976D2\">'+r.snapshot_id.slice(0,10)+'...</a></td>';",
        "          h+='<td>'+r.snapshot_type+'</td>';",
        "          h+='<td style=\"font-size:12px\">'+r.source_file+'</td>';",
        "          h+='<td style=\"font-size:11px\">'+c+'</td>';",
        "          h+='</tr>';",
        "        });",
        "        h+='</tbody></table>';",
        "      }",
        "      det(h);",
        "    })",
        "    .catch(function(e){det('<p class=\"hfail\">'+e.message+'</p>');});",
        "}",

        "document.addEventListener('click',function(e){",
        "  if(e.target.matches('.snap-det-link')){",
        "    e.preventDefault();",
        "    showSnapDetailInDet(e.target.getAttribute('data-sid'));",
        "  }",
        "});",

        "function showSnapDetailInDet(sid){",
        "  det('<p>Loading snapshot '+sid.slice(0,10)+'...</p>');",
        "  fetch('/api/snapshots/'+encodeURIComponent(sid))",
        "    .then(function(r){return r.json();})",
        "    .then(function(d){",
        "      if(d.error){det('<p class=\"hfail\">'+d.error+'</p>');return;}",
        "      var h='<p><strong>'+d.snapshot_type+'</strong> &mdash; '+d.source_file+'</p>';",
        "      h+='<p style=\"font-size:11px;color:#777;margin-bottom:8px\">'+d.snapshot_id+'</p>';",
        "      h+='<pre style=\"background:#f5f5f5;padding:10px;border-radius:4px;font-size:11px;max-height:500px;overflow-y:auto;white-space:pre-wrap;word-break:break-word\">';",
        "      h+=JSON.stringify(d.field_values,null,2).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');",
        "      h+='</pre>';",
        "      det(h);",
        "    })",
        "    .catch(function(e){det('<p class=\"hfail\">'+e.message+'</p>');});",
        "}",

        "function doTableDelete(pid){",
        "  if(!confirm('Delete project: '+pid+'? Cannot be undone.'))return;",
        "  fetch('/api/projects/'+encodeURIComponent(pid),{method:'DELETE'})",
        "    .then(function(r){return r.json();})",
        "    .then(function(d){if(d.ok){document.getElementById('det').innerHTML='';loadProjects();}else alert('Delete failed: '+d.error);})",
        "    .catch(function(e){alert(e.message);});",
        "}",

        "function res(id,ok,msg){var el=document.getElementById(id);el.innerHTML=msg;el.className='rb '+(ok?'ok':'err');el.style.display='block';}",

        "function doClone(){",
        "  var u=document.getElementById('clone-url').value.trim();",
        "  if(!u){res('clone-res',false,'Repository URL required');return;}",
        "  res('clone-res',true,'Cloning...');",
        "  fetch('/api/clone-github',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({repo_url:u})})",
        "    .then(function(r){return r.json();})",
        "    .then(function(d){if(d.ok)res('clone-res',true,'Done. project_id='+d.project_id);else res('clone-res',false,d.error||'Clone failed');})",
        "    .catch(function(e){res('clone-res',false,e.message);});",
        "}",

        "function doStage(){",
        "  var pid=document.getElementById('stage-pid').value.trim();",
        "  var src=document.getElementById('stage-path').value.trim();",
        "  if(!pid||!src){res('stage-res',false,'Project ID and Source Path required');return;}",
        "  res('stage-res',true,'Uploading...');",
        "  fetch('/api/staging/upload',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({project_id:pid,source_path:src})})",
        "    .then(function(r){return r.json();})",
        "    .then(function(d){if(d.ok)res('stage-res',true,'Staged '+d.files_staged+' files into staging/'+pid+'/');else res('stage-res',false,d.error||'Failed');})",
        "    .catch(function(e){res('stage-res',false,e.message);});",
        "}",

        "function doAdminDelete(){",
        "  var pid=document.getElementById('del-pid').value.trim();",
        "  if(!pid){res('del-res',false,'Project ID required');return;}",
        "  if(!confirm('Delete project: '+pid+'? Cannot be undone.'))return;",
        "  fetch('/api/projects/'+encodeURIComponent(pid),{method:'DELETE'})",
        "    .then(function(r){return r.json();})",
        "    .then(function(d){if(d.ok){res('del-res',true,'Deleted: '+pid);loadProjects();}else res('del-res',false,d.error||'Failed');})",
        "    .catch(function(e){res('del-res',false,e.message);});",
        "}",

        "function doQuerySnaps(){",
        "  var pid=document.getElementById('sq-pid').value.trim();",
        "  var st=document.getElementById('sq-type').value.trim();",
        "  var sf=document.getElementById('sq-file').value.trim();",
        "  if(!pid){res('sq-res',false,'Project ID required');return;}",
        "  var url='/api/projects/'+encodeURIComponent(pid)+'/snapshots?limit=100';",
        "  var p=[];if(st)p.push('type='+encodeURIComponent(st));if(sf)p.push('file='+encodeURIComponent(sf));",
        "  if(p.length)url+='&'+p.join('&');",
        "  res('sq-res',true,'Querying...');",
        "  fetch(url)",
        "    .then(function(r){return r.json();})",
        "    .then(function(d){",
        "      if(d.error){res('sq-res',false,d.error);return;}",
        "      var h='<strong>'+d.total+' snapshots</strong> across '+d.files+' files';",
        "      if(d.by_type&&Object.keys(d.by_type).length){",
        "        h+='<br><br><table style=\"width:auto\"><thead><tr><th>Type</th><th>Count</th></tr></thead><tbody>';",
        "        Object.keys(d.by_type).sort().forEach(function(k){h+='<tr><td>'+k+'</td><td>'+d.by_type[k]+'</td></tr>';});",
        "        h+='</tbody></table>';",
        "      }",
        "      if(d.records&&d.records.length){",
        "        h+='<br><br><strong>Records (first 100):</strong><br><table><thead><tr><th>Snapshot ID</th><th>Type</th><th>File</th></tr></thead><tbody>';",
        "        d.records.forEach(function(r){",
        "          h+='<tr>';",
        "          h+='<td><a href=\"#\" class=\"snap-link\" data-sid=\"'+r.snapshot_id+'\" style=\"font-family:monospace;font-size:11px;color:#1976D2;text-decoration:underline\">'+r.snapshot_id.slice(0,12)+'...</a></td>';",
        "          h+='<td>'+r.snapshot_type+'</td>';",
        "          h+='<td style=\"font-size:12px\">'+r.source_file+'</td>';",
        "          h+='</tr>';",
        "        });",
        "        h+='</tbody></table>';",
        "      }",
        "      res('sq-res',true,h);",
        "    })",
        "    .catch(function(e){res('sq-res',false,e.message);});",
        "}",

        "document.addEventListener('click',function(e){",
        "  if(e.target.matches('.snap-link')){",
        "    e.preventDefault();",
        "    var sid=e.target.getAttribute('data-sid');",
        "    showSnapshotDetail(sid);",
        "  }",
        "});",

        "function showSnapshotDetail(sid){",
        "  res('sq-res',true,'Loading snapshot '+sid.slice(0,12)+'...');",
        "  fetch('/api/snapshots/'+encodeURIComponent(sid))",
        "    .then(function(r){return r.json();})",
        "    .then(function(d){",
        "      if(d.error){res('sq-res',false,d.error);return;}",
        "      var h='<h3 style=\"margin-bottom:10px\">Snapshot: '+sid.slice(0,16)+'...</h3>';",
        "      h+='<p><strong>Type:</strong> '+d.snapshot_type+'<br>';",
        "      h+='<strong>File:</strong> '+d.source_file+'<br>';",
        "      h+='<strong>Project:</strong> '+d.project_id+'<br>';",
        "      h+='<strong>Run:</strong> '+d.run_id+'</p>';",
        "      h+='<pre style=\"background:#f5f5f5;padding:10px;border-radius:4px;font-size:11px;max-height:400px;overflow-y:auto;white-space:pre-wrap;word-break:break-word\">'+JSON.stringify(d.field_values,null,2).replace(/</g,'&lt;').replace(/>/g,'&gt;')+'</pre>';",
        "      h+='<button class=\"btn gray\" style=\"margin-top:10px\" onclick=\"doQuerySnaps()\">Back to List</button>';",
        "      res('sq-res',true,h);",
        "    })",
        "    .catch(function(e){res('sq-res',false,e.message);});",
        "}",

        "function loadLogs(){",
        "  var lv=document.getElementById('log-level').value;",
        "  var box=document.getElementById('logbox');",
        "  box.innerHTML='<div class=\"ll DF\">Loading...</div>';",
        "  fetch('/api/logs?level='+lv+'&limit=300')",
        "    .then(function(r){return r.json();})",
        "    .then(function(d){if(d.error)throw new Error(d.error);LOGS=d.logs||[];filterLogs();})",
        "    .catch(function(e){document.getElementById('logbox').innerHTML='<div class=\"ll ER\">Error: '+e.message+'</div>';});",
        "}",

        "function filterLogs(){",
        "  var q=(document.getElementById('log-filter').value||'').toLowerCase();",
        "  var fl=LOGS.filter(function(l){var m=(l.message||l.msg||JSON.stringify(l)).toLowerCase();return !q||m.indexOf(q)!==-1;});",
        "  var box=document.getElementById('logbox');",
        "  if(!fl.length){box.innerHTML='<div class=\"ll DF\">No logs found.</div>';return;}",
        "  box.innerHTML=fl.map(function(l){",
        "    var lv=((l.level||'INFO')+'').toUpperCase();",
        "    var cls=lv==='ERROR'?'ER':lv==='WARNING'?'WA':lv==='INFO'?'IN':lv==='DEBUG'?'DB':'DF';",
        "    var ts=l.timestamp?l.timestamp.replace('T',' ').slice(0,19):'';",
        "    var msg=(l.message||l.msg||JSON.stringify(l)).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');",
        "    return '<div class=\"ll '+cls+'\">['+ts+'] ['+lv+'] '+msg+'</div>';",
        "  }).join('');",
        "  box.scrollTop=box.scrollHeight;",
        "}",

        "function updateIngestStatus(d){",
        "  var dot=document.getElementById('ingest-dot');",
        "  var lbl=document.getElementById('ingest-status-lbl');",
        "  if(d.error){",
        "    dot.style.background='#F44336';",
        "    lbl.textContent='Error: '+d.error;",
        "    lbl.style.color='#D32F2F';",
        "  }else if(d.running){",
        "    dot.style.background='#4CAF50';",
        "    lbl.textContent='Running (staging + repos watchers active)';",
        "    lbl.style.color='#388E3C';",
        "  }else{",
        "    dot.style.background='#F44336';",
        "    lbl.textContent='Stopped';",
        "    lbl.style.color='#D32F2F';",
        "  }",
        "}",

        "function pollIngestStatus(){",
        "  fetch('/api/ingest/status').then(function(r){return r.json();}).then(updateIngestStatus).catch(function(){});",
        "}",

        "function doIngestStart(){",
        "  res('ingest-res',true,'Starting ingest watchers...');",
        "  fetch('/api/ingest/start',{method:'POST'})",
        "    .then(function(r){return r.json();})",
        "    .then(function(d){",
        "      if(d.ok){res('ingest-res',true,d.msg||'Ingest watchers starting');setTimeout(pollIngestStatus,2000);}",
        "      else res('ingest-res',false,d.error||'Failed to start');",
        "    })",
        "    .catch(function(e){res('ingest-res',false,e.message);});",
        "}",

        "function doIngestStop(){",
        "  res('ingest-res',true,'Stopping ingest watchers...');",
        "  fetch('/api/ingest/stop',{method:'POST'})",
        "    .then(function(r){return r.json();})",
        "    .then(function(d){",
        "      if(d.ok){res('ingest-res',true,'Ingest watchers stopped.');pollIngestStatus();}",
        "      else res('ingest-res',false,d.error||'Failed to stop');",
        "    })",
        "    .catch(function(e){res('ingest-res',false,e.message);});",
        "}",

        "loadProjects();",
        "setInterval(loadProjects,30000);",
        "pollIngestStatus();",
        "setInterval(pollIngestStatus,5000);",
    ]

    js = "<script>" + "\n".join(js_lines) + "</script>"

    return (
        "<!DOCTYPE html><html><head>"
        "<meta charset='utf-8'><title>SNAP Dashboard</title>"
        + css +
        "</head><body>"
        + html_body
        + js +
        "</body></html>"
    )


@app.route("/")
def dashboard():
    return Response(_html(), mimetype="text/html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

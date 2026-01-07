from flask import Blueprint, request, jsonify
from db import get_db
from utils.filters import build_filters

logs_bp = Blueprint("logs_bp", __name__)

@logs_bp.route("/api/logs")
def api_logs():
    db = get_db()
    where, params = build_filters(request)

    query = f"""
        SELECT id, timestamp, ip, method, path, full_url,
               status, user_agent, payload_preview, threat_score
        FROM logs
        {where}
        ORDER BY timestamp DESC
        LIMIT 100
    """
    rows = db.execute(query, params).fetchall()

    logs = [{
        "id": r["id"],
        "timestamp": r["timestamp"],
        "ip": r["ip"],
        "method": r["method"],
        "path": r["path"],
        "full_url": r["full_url"],
        "status": r["status"],
        "user_agent": r["user_agent"],
        "payload": r["payload_preview"],
        "threat_score": r["threat_score"]
    } for r in rows]

    return jsonify({"logs": logs})

@logs_bp.route("/log", methods=["POST"])
def receive_log():
    try:
        data = request.get_json()
        full_url = data.get("full_url", "-")
        ip = data.get("ip", "-")
        path = data.get("url", "-")
        method = data.get("method", "-")
        ua = data.get("ua", "")
        status = data.get("status", 200)
        payload_raw = data.get("payload", "")

        if isinstance(payload_raw, dict):
            payload_preview = str(payload_raw)[:1000]
        else:
            payload_preview = payload_raw[:1000]

        db = get_db()
        db.execute("""
            INSERT INTO logs 
            (timestamp, ip, method, path, full_url, status, payload_preview, user_agent, threat_score)
            VALUES (DATETIME('now','+8 hours'), ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ip, method, path, full_url, status, payload_preview, ua, 0))

        db.commit()
        return jsonify({"status": "ok"}), 200
    except Exception as e:
        print("LOG ERROR:", e)
        return jsonify({"status": "error"}), 400

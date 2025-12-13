from flask import Flask, request, jsonify, render_template
from db import get_db, close_db, init_db, init_db_command

app = Flask(__name__)
app.teardown_appcontext(close_db)

# Daftarkan CLI
init_db_command(app)


# ============================
# Dashboard
# ============================
@app.route("/")
def dashboard():
    return render_template("index.html")


# ============================
# API: GET Logs
# ============================
@app.route("/api/logs")
def api_logs():
    db = get_db()
    rows = db.execute("""
        SELECT id, timestamp, ip, method, path,full_url, status, user_agent, payload_preview, threat_score
        FROM logs
        ORDER BY id DESC
        LIMIT 20
    """).fetchall()

    logs = [
        {
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
        }
        for r in rows
    ]

    return jsonify({"logs": logs})


# ============================
# API: POST Log
# ============================
@app.route("/log", methods=["POST"])
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
            VALUES (DATETIME('now'), ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ip, method, path, full_url, status, payload_preview, ua, 0))

        db.commit()

        return jsonify({"status": "ok"}), 200

    except Exception as e:
        print("LOG ERROR:", e)
        return jsonify({"status": "error"}), 400


@app.route("/api/stats/requests")
def stats_requests():
    db = get_db()
    rows = db.execute("""
        SELECT strftime('%H:%M', timestamp) AS minute, COUNT(*) AS total
        FROM logs
        GROUP BY minute
        ORDER BY minute DESC
        LIMIT 20
    """).fetchall()

    return jsonify({
        "labels": [r["minute"] for r in rows][::-1],
        "values": [r["total"] for r in rows][::-1]
    })


@app.route("/api/stats/methods")
def stats_methods():
    db = get_db()
    rows = db.execute("""
        SELECT method, COUNT(*) AS total
        FROM logs
        GROUP BY method
    """).fetchall()

    return jsonify({
        "labels": [r["method"] for r in rows],
        "values": [r["total"] for r in rows]
    })

@app.route("/api/stats/status")
def stats_status():
    db = get_db()
    rows = db.execute("""
        SELECT status, COUNT(*) AS total
        FROM logs
        GROUP BY status
    """).fetchall()

    return jsonify({
        "labels": [str(r["status"]) for r in rows],
        "values": [r["total"] for r in rows]
    })


# ============================
# Run Server
# ============================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000, debug=True)

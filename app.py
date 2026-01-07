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

    filters = []
    params = []


    start = request.args.get("start")
    if start:
        filters.append("timestamp >= ?")
        params.append(start.replace("T", " ") + ":00")

    end = request.args.get("end")
    if end:
        filters.append("timestamp <= ?")
        params.append(end.replace("T", " ") + ":59")


    ip = request.args.get("ip")
    if ip:
        filters.append("ip LIKE ?")
        params.append(f"%{ip}%")

    method = request.args.get("method")
    if method:
        filters.append("method = ?")
        params.append(method)

    status = request.args.get("status")
    if status:
        filters.append("status = ?")
        params.append(status)

    where_clause = ""
    if filters:
        where_clause = "WHERE " + " AND ".join(filters)

    query = f"""
        SELECT id, timestamp, ip, method, path, full_url,
               status, user_agent, payload_preview, threat_score
        FROM logs
        {where_clause}
        ORDER BY timestamp  DESC
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



def build_filters(request):
    filters = []
    params = []

    start = request.args.get("start")
    if start:
        filters.append("timestamp >= ?")
        params.append(start.replace("T", " ") + ":00")

    end = request.args.get("end")
    if end:
        filters.append("timestamp <= ?")
        params.append(end.replace("T", " ") + ":59")

    ip = request.args.get("ip")
    if ip:
        filters.append("ip LIKE ?")
        params.append(f"%{ip}%")

    method = request.args.get("method")
    if method:
        filters.append("method = ?")
        params.append(method)

    status = request.args.get("status")
    if status:
        filters.append("status = ?")
        params.append(status)

    where_clause = ""
    if filters:
        where_clause = "WHERE " + " AND ".join(filters)

    return where_clause, params


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
            VALUES (DATETIME('now','+8 hours'), ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ip, method, path, full_url, status, payload_preview, ua, 0))

        db.commit()

        return jsonify({"status": "ok"}), 200

    except Exception as e:
        print("LOG ERROR:", e)
        return jsonify({"status": "error"}), 400


@app.route("/api/stats/requests")
def stats_requests():
    db = get_db()
    where, params = build_filters(request)

    rows = db.execute(f"""
        SELECT strftime('%H:%M', timestamp) AS minute, COUNT(*) AS total
        FROM logs
        {where}
        GROUP BY minute
        ORDER BY minute
    """, params).fetchall()

    return jsonify({
        "labels": [r["minute"] for r in rows],
        "values": [r["total"] for r in rows]
    })

@app.route("/api/stats/methods")
def stats_methods():
    db = get_db()
    where, params = build_filters(request)

    rows = db.execute(f"""
        SELECT method, COUNT(*) AS total
        FROM logs
        {where}
        GROUP BY method
    """, params).fetchall()

    return jsonify({
        "labels": [r["method"] for r in rows],
        "values": [r["total"] for r in rows]
    })

@app.route("/api/stats/status")
def stats_status():
    db = get_db()
    where, params = build_filters(request)

    rows = db.execute(f"""
        SELECT status, COUNT(*) AS total
        FROM logs
        {where}
        GROUP BY status
    """, params).fetchall()

    return jsonify({
        "labels": [str(r["status"]) for r in rows],
        "values": [r["total"] for r in rows]
    })

# ============================
# Run Server
# ============================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000, debug=True)

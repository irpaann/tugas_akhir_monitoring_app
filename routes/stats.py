from flask import Blueprint, request, jsonify
from db import get_db
from utils.filters import build_filters

stats_bp = Blueprint("stats_bp", __name__)

@stats_bp.route("/api/stats/requests")
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

@stats_bp.route("/api/stats/methods")
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

@stats_bp.route("/api/stats/status")
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

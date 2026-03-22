from flask import request, jsonify, session, redirect, url_for, make_response
from db import get_db
from datetime import datetime, timedelta
from models.rule_engine import check_rule_based
import os
import io
import csv

def register_api(app):
    
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

    @app.route("/api/blacklist")
    def api_blacklist():
        db = get_db()
        
        # 1. Bersihkan status yang sudah expired SETIAP KALI halaman dibuka
        db.execute("""
            UPDATE blacklist_ip 
            SET is_active = 0 
            WHERE is_active = 1 AND expires_at < DATETIME('now', '+8 hours')
        """)
        db.commit() # Penting untuk commit agar tersimpan

        # 2. Baru ambil datanya
        rows = db.execute("""
            SELECT id, ip, reason, blocked_at, expires_at, blocked_by, 
                is_active, total_hits, last_seen
            FROM blacklist_ip
            ORDER BY blocked_at DESC
        """).fetchall()

        data = [dict(r) for r in rows]
        return jsonify({"ips": data})

    @app.route("/api/blacklist/check", methods=["GET"])
    def check_ip():
        ip = request.args.get("ip")
        db = get_db()
        
        # Cari IP yang status is_active-nya masih 1
        row = db.execute(
            "SELECT reason FROM blacklist_ip WHERE ip = ? AND is_active = 1", 
            (ip,)
        ).fetchone()
        
        if row:
            return {"is_active": True, "reason": row["reason"]}, 200
        
        return {"is_active": False}, 200


    @app.route("/api/blacklist/stats")
    def api_blacklist_stats():
        db = get_db()

        row = db.execute("""
            SELECT
                COUNT(*) AS total,
                SUM(is_active) AS active,
                SUM(CASE WHEN is_active = 0 THEN 1 ELSE 0 END) AS expired
            FROM blacklist_ip
        """).fetchone()

        return jsonify({
            "total": row["total"],
            "active": row["active"] or 0,
            "expired": row["expired"] or 0
        })



    # ============================
    # API: POST Log
    # ============================
    @app.route("/log", methods=["POST"])
    def receive_log():
        data = request.get_json()
        attack_type = data.get("reason")
        client_ip = data.get("ip")
        db = get_db()

        # Ubah is_active jadi 0 jika sudah lewat dari waktu expires_at
        db.execute("""
            UPDATE blacklist_ip 
            SET is_active = 0 
            WHERE is_active = 1 AND expires_at < DATETIME('now', '+8 hours')
        """)

        # 1. Ambil data blacklist terakhir (meskipun sudah tidak aktif/is_active=0)
        # Ini penting agar kita tahu ini pelanggaran ke-berapa bagi IP tersebut
        history = db.execute(
            "SELECT total_hits FROM blacklist_ip WHERE ip = ? ORDER BY id DESC LIMIT 1", 
            (client_ip,)
        ).fetchone()

        # Tentukan jumlah pelanggaran (jika belum pernah, maka 1)
        violation_count = (history["total_hits"] + 1) if history else 1

        base_minutes = 10
        total_duration_minutes = base_minutes * violation_count

        if attack_type:
            existing = db.execute(
                "SELECT id FROM blacklist_ip WHERE ip = ? AND is_active = 1", 
                (client_ip,)
            ).fetchone()

            if not existing:
                # INSERT Baru dengan durasi dinamis
                db.execute(f"""
                    INSERT INTO blacklist_ip (
                        ip, reason, blocked_at, expires_at, blocked_by, is_active, total_hits, last_seen
                    )
                    VALUES (?, ?, DATETIME('now','+8 hours'), 
                    DATETIME('now','+8 hours', '+{total_duration_minutes} seconds'), 
                    'WAF-System', 1, ?, DATETIME('now','+8 hours'))
                """, (client_ip, attack_type, violation_count))
            else:
                # UPDATE Hits dan Perpanjang Durasi jika dia menyerang lagi saat masih diblokir
                db.execute(f"""
                    UPDATE blacklist_ip 
                    SET total_hits = total_hits + 1, 
                        last_seen = DATETIME('now','+8 hours'),
                        expires_at = DATETIME(expires_at, '+{base_minutes} seconds') 
                    WHERE ip = ? AND is_active = 1
                """, (client_ip,))

        # 3. Simpan Log (seperti biasa)
        db.execute("""
            INSERT INTO logs (timestamp, ip, path, full_url, method, status, payload_preview, reason, user_agent)
            VALUES (DATETIME('now','+8 hours'), ?, ?, ?, ?, ?, ?, ?, ?)
        """, (client_ip, data.get("url"), data.get("full_url"), data.get("method"), 
            data.get("status"), str(data.get("payload"))[:200], attack_type, data.get("ua")))
        
        db.commit()
        return {"status": "success", "duration_added": total_duration_minutes}, 200

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

    @app.route("/api/blacklist/block", methods=["POST"])
    def api_block_ip():
        data = request.get_json()

        ip = data.get("ip")
        reason = data.get("reason", "Manual block")
        duration = data.get("duration", 24)  # jam
        blocked_by = data.get("blocked_by", "admin")

        if not ip:
            return jsonify({"error": "IP is required"}), 400

        blocked_at = datetime.now()
        expires_at = blocked_at + timedelta(hours=int(duration))

        db = get_db()

        # Cek apakah IP sudah ada
        existing = db.execute(
            "SELECT id FROM blacklist_ip WHERE ip = ? AND is_active = 1",
            (ip,)
        ).fetchone()

        if existing:
            return jsonify({"error": "IP already blocked"}), 400

        db.execute("""
            INSERT INTO blacklist_ip
            (ip, reason, blocked_at, expires_at, blocked_by, is_active)
            VALUES (?, ?, ?, ?, ?, 1)
        """, (
            ip,
            reason,
            blocked_at,
            expires_at,
            blocked_by
        ))

        db.commit()

        return jsonify({"status": "blocked", "ip": ip})


    @app.route("/api/blacklist/unblock", methods=["POST"])
    def api_unblock_ip():
        data = request.get_json()
        ip = data.get("ip")
        db = get_db()

        # Opsi 1: Hapus total agar hitungan pelanggaran kembali ke 0
        db.execute("DELETE FROM blacklist_ip WHERE ip = ?", (ip,))
        
        # Opsi 2 (Jika ingin tetap ada riwayat tapi tidak memblokir):
        # db.execute("UPDATE blacklist_ip SET is_active = 0, total_hits = 0 WHERE ip = ?", (ip,))

        db.commit()
        return jsonify({"status": "unblocked", "ip": ip})
    
    @app.route("/api/logs/export", methods=["GET"])
    def export_logs():
        db = get_db()
        logs = db.execute("SELECT * FROM logs ORDER BY id DESC").fetchall()

        if not logs:
            return "Tidak ada data untuk diekspor", 404

        output = io.StringIO()
        writer = csv.writer(output)

        # Ambil nama kolom secara dinamis dari database agar tidak IndexError lagi
        column_names = logs[0].keys()
        writer.writerow(column_names) # Tulis header otomatis sesuai database

        # Tulis baris data
        for log in logs:
            writer.writerow([log[column] for column in column_names])

        response = make_response(output.getvalue())
        response.headers["Content-Disposition"] = "attachment; filename=waf_logs_export.csv"
        response.headers["Content-type"] = "text/csv"
        return response

    # LOGIN API (Simpan di sini agar satu grup dengan login_page)
    @app.route("/api/auth/login", methods=["POST"])
    def do_login():
        data = request.get_json()
        username_input = data.get("username")
        password_input = data.get("password")

        # Mengambil data dari .env
        env_user = os.getenv("ADMIN_USERNAME")
        env_pass = os.getenv("ADMIN_PASSWORD")

        if username_input == env_user and password_input == env_pass:
            session["logged_in"] = True
            session["user"] = env_user
            return jsonify({"status": "success"}), 200
        
        return jsonify({"status": "failed", "message": "Kredensial Salah"}), 401

    @app.route("/logout")
    def logout():
        session.clear() # Menghapus semua data session
        return redirect(url_for("login_page"))
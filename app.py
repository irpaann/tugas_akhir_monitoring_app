import os
import logging
from flask import Flask, request, abort, render_template
from db import close_db, init_db_command, get_db
from dotenv import load_dotenv 

# Import Business Logic
from routes.routes import register_routes
from routes.api import register_api
from models.rule_engine import check_rule_based

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "default_secret_key")
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# ==========================================
# 1. KONFIGURASI & INISIALISASI
# ==========================================
app.teardown_appcontext(close_db)
init_db_command(app)

@app.errorhandler(403)
def forbidden(e):
    """Handler khusus untuk menampilkan halaman blokir."""
    return render_template('pages/blocked.html', reason=e.description), 403

# ==========================================
# 2. MIDDLEWARE (Security Filter)
# ==========================================

@app.before_request
def security_filter():
    path = request.path
    
    # 1. Izinkan file statis (CSS/JS/Images) agar halaman blokir tampil rapi
    if path.startswith('/static'):
        return

    # 2. Ambil IP Client
    client_ip = request.remote_addr
    # Jika menggunakan Docker/Nginx, pastikan mendapatkan IP asli:
    # client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)

    db = get_db()
    
    # 3. Cek apakah IP aktif di blacklist DAN belum expired
    # Gunakan pengecekan waktu agar IP otomatis lepas blokir setelah 10/20/30 detik
    blocked = db.execute("""
        SELECT reason FROM blacklist_ip 
        WHERE ip = ? AND is_active = 1 
        AND expires_at > DATETIME('now', '+8 hours')
    """, (client_ip,)).fetchone()
    
    if blocked:
        # Jika IP diblokir, JANGAN izinkan akses ke mana pun kecuali halaman statis
        # Termasuk memblokir akses ke /api/ dan halaman lainnya
        abort(403, description=blocked['reason'])

# ==========================================
# 3. REGISTER ROUTES & RUNNER
# ==========================================

register_routes(app)
register_api(app)

if __name__ == "__main__":
    # Pastikan host 0.0.0.0 agar bisa diakses oleh aplikasi user (Web Testing)
    app.run(host="0.0.0.0", port=3000, debug=True)
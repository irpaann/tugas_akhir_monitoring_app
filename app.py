import os
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
    # JANGAN memfilter path API dan Log agar komunikasi antar container lancar
    if path.startswith('/static') or path.startswith('/api/') or path == '/log':
        return

    # Dashboard hanya memblokir jika IP penyerang mencoba mengakses halaman Dashboard itu sendiri
    db = get_db()
    client_ip = request.remote_addr
    blocked = db.execute("SELECT reason FROM blacklist_ip WHERE ip = ? AND is_active = 1", (client_ip,)).fetchone()
    
    if blocked:
        abort(403, description=blocked['reason'])

# ==========================================
# 3. REGISTER ROUTES & RUNNER
# ==========================================

register_routes(app)
register_api(app)

if __name__ == "__main__":
    # Pastikan host 0.0.0.0 agar bisa diakses oleh aplikasi user (Web Testing)
    app.run(host="0.0.0.0", port=3000, debug=True)
from flask import Flask
from db import close_db, init_db_command
from routes.dashboard import dashboard_bp
from routes.logs import logs_bp
from routes.stats import stats_bp

app = Flask(__name__)
app.teardown_appcontext(close_db)
init_db_command(app)

# Register blueprint
app.register_blueprint(dashboard_bp)
app.register_blueprint(logs_bp)
app.register_blueprint(stats_bp)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3000, debug=True)

# app.py

import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from werkzeug.middleware.proxy_fix import ProxyFix
from sqlalchemy.orm import DeclarativeBase
from ultra_cache import preload_critical_data

# Konfigurasi logging (hanya error untuk performa)
logging.basicConfig(level=logging.ERROR)

# Base class SQLAlchemy
class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

# Inisiasi Flask App
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Konfigurasi Database ULTRA
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
    "pool_size": 100,
    "max_overflow": 200,
    "pool_timeout": 5,
    "echo": False,
    "connect_args": {
        "application_name": "strong_warehouse_ultra_10x",
        "connect_timeout": 2,
        "sslmode": "require"
    }
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Inisialisasi DB
db.init_app(app)

# Import semua model dan route
with app.app_context():
    import database_models
    import routes
    import attendance_routes
    from attendance_routes import init_attendance_routes
    init_attendance_routes(app)
    db.create_all()

    # Preload data penting
    try:
        preload_critical_data()
    except Exception as e:
        logging.error(f"Gagal preload cache: {e}")

# START POINT untuk Gunicorn
if __name__ == "__main__":
    app.run(debug=True)

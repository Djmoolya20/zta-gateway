import os
from pathlib import Path

from flask import Flask
from .models import db, User
from werkzeug.security import generate_password_hash
from sqlalchemy import event
from sqlalchemy.engine import Engine

# Load .env file (non-overriding: env vars already set take precedence)
try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=Path(__file__).parent.parent / ".env", override=False)
except ImportError:
    pass  # python-dotenv not installed; env vars must be set externally

# Enable SQLite WAL mode for better concurrency (readers don't block writers)
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.execute("PRAGMA busy_timeout=5000;")  # 5s busy timeout
    cursor.close()

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "change-this-later"
    # Tests set ZTA_DB to a throwaway database so they never collide with the
    # live server's db/zta.db (which a soak-testing run.py may have open).
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "ZTA_DB", "sqlite:///../db/zta.db")

    # Connection pool settings for SQLite (helps with concurrent threads)
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_pre_ping": True,
        "pool_recycle": 300,
        "connect_args": {"check_same_thread": False},
    }

    db.init_app(app)

    with app.app_context():
        db.create_all()
        # create a default admin user if none exists (Phase 1 shortcut)
        if not User.query.filter_by(username="admin").first():
            admin = User(username="admin",
                         email="admin@local",
                         password_hash=generate_password_hash("admin123"),
                         status="approved",
                         is_admin=True,
                         email_verified=True)
            db.session.add(admin)
            db.session.commit()

    from .routes import main
    app.register_blueprint(main)

    # Phase 7 captive portal: gate unapproved devices at the login page.
    from .middleware import captive_portal_check
    app.before_request(captive_portal_check)

    return app

import secrets
import re
import json
import os
from functools import wraps
from collections import defaultdict

from flask import (Blueprint, render_template, request, redirect, session,
                   url_for, flash, current_app)
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime, timedelta
from sqlalchemy.exc import IntegrityError
from sqlalchemy import func
from .models import User, Device, AuthEvent, Ban, db, RiskHistory, DNSLog, BandwidthLog
from .enforcement.quarantine import release_device
from .logging.forensic import log_forensic_event
from .traceback.tracer import reconstruct_timeline
from .mail import send_verification_email, send_otp_email
from .auth.otp import (generate_otp, set_otp, clear_otp, verify_otp as check_otp,
                       is_otp_valid, can_resend_otp, increment_otp_attempts)

main = Blueprint("main", __name__)

# In-memory rate limiting (per IP, 15-min window)
_register_attempts = defaultdict(list)
_login_attempts = defaultdict(list)
RATE_LIMIT_WINDOW = timedelta(minutes=15)
RATE_LIMIT_MAX = 5


# --- auth guards -----------------------------------------------------------

def _current_user():
    username = session.get("user")
    if not username:
        return None
    return User.query.filter_by(username=username).first()


def admin_required(f):
    """Phase 7 hardening: every /admin route must belong to an admin user.

    Closes the Phase 6 gap where any logged-in user could hit pending-approval
    / unban / traceback endpoints.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = _current_user()
        if not user:
            return redirect(url_for("main.login"))
        if not user.is_admin:
            return "Forbidden — admin access required.", 403
        return f(*args, **kwargs)
    return wrapper


# --- auth flow -------------------------------------------------------------

@main.route("/login", methods=["GET", "POST"])
def login():
    # Rate limiting on login
    client_ip = request.remote_addr
    if not check_rate_limit(_login_attempts, client_ip):
        db.session.add(AuthEvent(username="(rate-limited)", ip=client_ip, result="Failed"))
        db.session.commit()
        return "Too many login attempts. Please wait 15 minutes.", 429

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        success = bool(user) and check_password_hash(user.password_hash, password)

        db.session.add(AuthEvent(
            username=username,
            ip=client_ip,
            result="Success" if success else "Failed",
        ))
        db.session.commit()

        if not success:
            record_attempt(_login_attempts, client_ip)
            return "Invalid credentials", 401
        if not user.email_verified:
            record_attempt(_login_attempts, client_ip)
            return "Please verify your email first.", 403
        if user.status != "approved":
            record_attempt(_login_attempts, client_ip)
            return "Your account is pending admin approval.", 403

        # Update last login info
        user.last_login = datetime.utcnow()
        user.last_login_ip = client_ip
        db.session.commit()

        session["user"] = user.username
        return redirect(url_for("main.admin_dashboard"))

    # Clean old login attempts on GET
    now = datetime.utcnow()
    cutoff = now - RATE_LIMIT_WINDOW
    for ip in list(_login_attempts.keys()):
        _login_attempts[ip] = [ts for ts in _login_attempts[ip] if ts > cutoff]
        if not _login_attempts[ip]:
            del _login_attempts[ip]

    return render_template("login.html")


# --- validation helpers ------------------------------------------------------

USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_]{3,30}$")
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def validate_registration(username: str, email: str, password: str, confirm: str):
    """Return error message string if validation fails, None if valid."""
    if not username or not password or not email:
        return "Username, email and password are all required."
    if not USERNAME_PATTERN.match(username):
        return "Username must be 3-30 characters, alphanumeric or underscore only."
    if not EMAIL_PATTERN.match(email):
        return "Invalid email format."
    # Password strength: min 7 chars (tests use 7), at least 1 letter and 1 digit
    if len(password) < 7:
        return "Password must be at least 7 characters."
    if not re.search(r"[A-Za-z]", password):
        return "Password must contain at least one letter."
    if not re.search(r"\d", password):
        return "Password must contain at least one digit."
    if password != confirm:
        return "Passwords do not match."
    return None


def check_rate_limit(attempts_dict: dict, ip: str) -> bool:
    """Return True if under rate limit, False if exceeded. Cleans old entries."""
    now = datetime.utcnow()
    cutoff = now - RATE_LIMIT_WINDOW
    # Clean old entries
    attempts_dict[ip] = [ts for ts in attempts_dict[ip] if ts > cutoff]
    return len(attempts_dict[ip]) < RATE_LIMIT_MAX


def record_attempt(attempts_dict: dict, ip: str):
    """Record a new attempt for the given IP."""
    attempts_dict[ip].append(datetime.utcnow())


@main.route("/register", methods=["GET", "POST"])
def register():
    # Rate limiting on registration
    client_ip = request.remote_addr
    if not check_rate_limit(_register_attempts, client_ip):
        # Still record AuthEvent for rate-limited attempt
        db.session.add(AuthEvent(username="(rate-limited)", ip=client_ip, result="Failed"))
        db.session.commit()
        return "Too many registration attempts. Please wait 15 minutes.", 429

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        # Validation (preserve existing 400 responses for duplicates/mismatch)
        error = validate_registration(username, email, password, confirm)
        if error:
            # Check if it's a duplicate error to preserve test-expected messages
            if User.query.filter_by(username=username).first():
                return "Username already taken.", 400
            if User.query.filter_by(email=email).first():
                return "Email already registered.", 400
            if password != confirm:
                return "Passwords do not match.", 400
            return error, 400

        # Check duplicates (preserve existing behavior for tests)
        if User.query.filter_by(username=username).first():
            return "Username already taken.", 400
        if User.query.filter_by(email=email).first():
            return "Email already registered.", 400

        # Auto-detect device info from registration IP
        device = Device.query.filter_by(ip=client_ip).first()
        claimed_mac = device.mac if device else None
        claimed_hostname = device.hostname if device else None

        token = secrets.token_urlsafe(32)
        otp = generate_otp()
        try:
            user = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password),
                status="pending",
                is_admin=False,
                verification_token=token,
                registration_ip=client_ip,
                registration_ua=request.headers.get("User-Agent"),
                claimed_mac=claimed_mac,
                claimed_hostname=claimed_hostname,
            )
            set_otp(user, otp)
            db.session.add(user)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return "Username or email already registered.", 400

        # Send both verification link (for backward compat) and OTP
        verify_url = url_for("main.verify_email", token=token, _external=True)
        send_verification_email(current_app._get_current_object(),
                                email, username, verify_url)
        send_otp_email(current_app._get_current_object(),
                       email, username, otp)

        record_attempt(_register_attempts, client_ip)

        flash("Registration submitted. Check your email (or the server console "
              "in lab mode) for the verification code, then verify below.")
        return redirect(url_for("main.verify_otp_page"))
    return render_template("register.html")


@main.route("/verify/<token>")
def verify_email(token):
    user = User.query.filter_by(verification_token=token).first()
    if not user:
        return "Invalid or expired verification link.", 400
    user.email_verified = True
    user.verification_token = None   # one-time use
    db.session.commit()
    return render_template("verify_success.html", username=user.username)


# --- OTP verification flow (Task 2) -----------------------------------------

@main.route("/verify-otp", methods=["GET"])
def verify_otp_page():
    """Render OTP entry page."""
    return render_template("verify_otp.html")


@main.route("/verify-otp", methods=["POST"])
def verify_otp():
    """Verify submitted OTP code."""
    otp = request.form.get("otp", "").strip()
    email = request.form.get("email", "").strip()
    client_ip = request.remote_addr

    if not otp or not email:
        return render_template("verify_otp.html", error="Email and OTP are required.", email=email)

    user = User.query.filter_by(email=email).first()
    if not user:
        # Don't reveal if email exists
        db.session.add(AuthEvent(username=f"(otp:{email})", ip=client_ip, result="Failed"))
        db.session.commit()
        log_forensic_event("unknown", "OTP_FAILED", {"email": email, "reason": "user_not_found"})
        return render_template("verify_otp.html", error="Invalid code. Please try again.", email=email)

    if not is_otp_valid(user):
        if user.otp_expires_at and datetime.utcnow() > user.otp_expires_at:
            error = "Code expired. Please request a new one."
        elif user.otp_attempts >= 5:
            error = "Too many failed attempts. Please request a new code."
        else:
            error = "Invalid code. Please try again."
        db.session.add(AuthEvent(username=user.username, ip=client_ip, result="Failed"))
        db.session.commit()
        log_forensic_event(user.username, "OTP_FAILED", {"email": email, "attempts": user.otp_attempts + 1})
        return render_template("verify_otp.html", error=error, email=email)

    if not check_otp(otp, user.otp_hash):
        increment_otp_attempts(user)
        db.session.add(AuthEvent(username=user.username, ip=client_ip, result="Failed"))
        db.session.commit()
        log_forensic_event(user.username, "OTP_FAILED", {"email": email, "attempts": user.otp_attempts})
        remaining = 5 - user.otp_attempts
        return render_template("verify_otp.html",
                               error=f"Invalid code. {remaining} attempt(s) remaining.",
                               email=email)

    # Success!
    user.email_verified = True
    clear_otp(user)
    db.session.commit()

    flash("Email verified! You can now log in. If an admin hasn't approved your account yet, you'll be asked to wait.")
    return redirect(url_for("main.login"))


@main.route("/resend-otp", methods=["POST"])
def resend_otp():
    """Resend OTP code (with 60s cooldown)."""
    email = request.form.get("email", "").strip()
    client_ip = request.remote_addr

    if not email:
        return render_template("verify_otp.html", error="Email is required.", email=email)

    user = User.query.filter_by(email=email).first()
    if not user:
        # Don't reveal if email exists
        return render_template("verify_otp.html", error="If the email exists, a new code has been sent.", email=email)

    if not can_resend_otp(user):
        remaining = int(60 - (datetime.utcnow() - user.otp_last_sent).total_seconds())
        return render_template("verify_otp.html",
                               error=f"Please wait {remaining}s before requesting a new code.",
                               email=email)

    otp = generate_otp()
    set_otp(user, otp)
    db.session.commit()

    send_otp_email(current_app._get_current_object(), email, user.username, otp)
    log_forensic_event(user.username, "OTP_RESENT", {"email": email})

    return render_template("verify_otp.html",
                           message="A new code has been sent. Check your email (or server console in lab mode).",
                           email=email)


# --- admin console ----------------------------------------------------------

@main.route("/admin/pending")
@admin_required
def pending_users():
    pending = User.query.filter_by(status="pending").order_by(
        User.registered_at.asc()).all()
    return render_template("pending_users.html", pending=pending)


@main.route("/admin/approve/<int:user_id>", methods=["POST"])
@admin_required
def approve_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return "User not found", 404
    user.status = "approved"
    db.session.commit()
    log_forensic_event(user.username, "USER_APPROVED",
                       f"Approved registration for {user.username}")
    return redirect(url_for("main.pending_users"))


@main.route("/admin/reject/<int:user_id>", methods=["POST"])
@admin_required
def reject_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return "User not found", 404
    user.status = "rejected"
    db.session.commit()
    log_forensic_event(user.username, "USER_REJECTED",
                       f"Rejected registration for {user.username}")
    return redirect(url_for("main.pending_users"))


@main.route("/admin")
@admin_required
def admin_dashboard():
    devices = Device.query.all()
    active_bans = Ban.query.filter_by(active=True).order_by(Ban.since.desc()).all()
    pending = User.query.filter_by(status="pending").all()
    recent_events = (AuthEvent.query
                     .order_by(AuthEvent.timestamp.desc())
                     .limit(20).all())
    # All users for the Users table
    users = User.query.order_by(User.registered_at.desc()).all()

    stats = {
        "total_devices": len(devices),
        "high_risk": sum(1 for d in devices if d.risk_level == "HIGH"),
        "medium_risk": sum(1 for d in devices if d.risk_level == "MEDIUM"),
        "active_bans": len(active_bans),
        "pending_users": len(pending),
        "total_users": len(users),
    }
    return render_template("admin.html", devices=devices,
                           active_bans=active_bans,
                           recent_events=recent_events,
                           pending_users=pending,
                           users=users,
                           stats=stats)


# Backwards-compat: the Phase 1-5 dashboard now lives at /admin.
@main.route("/dashboard")
@admin_required
def dashboard():
    return redirect(url_for("main.admin_dashboard"))


@main.route("/admin/unban/<mac>", methods=["POST"])
@admin_required
def unban(mac):
    ban = Ban.query.filter_by(mac=mac, active=True).first()
    if ban:
        ban.active = False
        ban.unbanned_at = datetime.utcnow()
    release_device(mac)
    device = Device.query.filter_by(mac=mac).first()
    if device:
        # Zero-trust choice: unban does NOT restore approval — it resets to
        # "unknown" so the device has to re-earn trust from scratch.
        device.status = "unknown"
    db.session.commit()
    log_forensic_event(mac, "UNBAN", "Released from quarantine (status -> unknown)")
    return redirect(url_for("main.admin_dashboard"))


@main.route("/admin/traceback/<mac>")
@admin_required
def traceback_view(mac):
    data = reconstruct_timeline(mac)
    return render_template("traceback.html", data=data)


# --- Admin dashboard enrichment (Task 4) ------------------------------------

@main.route("/admin/user/<int:user_id>")
@admin_required
def admin_user_detail(user_id):
    """Per-user drill-down with linked device risk breakdown."""
    user = User.query.get(user_id)
    if not user:
        return "User not found", 404

    # Find linked device by claimed_mac or by user field
    device = None
    if user.claimed_mac:
        device = Device.query.filter_by(mac=user.claimed_mac).first()
    if not device:
        device = Device.query.filter_by(user=user.username).first()

    # Get recent risk history for this device
    risk_history = []
    if device:
        risk_history = (RiskHistory.query
                        .filter_by(mac=device.mac)
                        .order_by(RiskHistory.timestamp.desc())
                        .limit(50).all())

    return render_template("admin_user_detail.html", user=user, device=device, risk_history=risk_history)


@main.route("/admin/device/<mac>")
@admin_required
def admin_device_detail(mac):
    """Per-device drill-down with risk breakdown."""
    device = Device.query.filter_by(mac=mac).first()
    if not device:
        return "Device not found", 404

    # Get linked user
    user = User.query.filter_by(username=device.user).first() if device.user else None

    # Get recent risk history
    risk_history = (RiskHistory.query
                    .filter_by(mac=mac)
                    .order_by(RiskHistory.timestamp.desc())
                    .limit(50).all())

    return render_template("admin_device_detail.html", device=device, user=user, risk_history=risk_history)


@main.route("/admin/report/domains")
@admin_required
def admin_domains_report():
    """Top domains report from DNSLog."""
    from sqlalchemy import func
    domains = (db.session.query(DNSLog.domain, func.count(DNSLog.id).label('count'),
                 func.sum(func.cast(DNSLog.flagged, db.Integer)).label('flagged_count'))
               .group_by(DNSLog.domain)
               .order_by(func.count(DNSLog.id).desc())
               .all())
    return render_template("admin_domains_report.html", domains=domains)


@main.route("/admin/report/bandwidth")
@admin_required
def admin_bandwidth_report():
    """Bandwidth report from BandwidthLog with hourly/daily rollups."""
    from sqlalchemy import func
    # Hourly rollups
    hourly = (db.session.query(BandwidthLog.mac,
                  func.strftime('%Y-%m-%d %H', BandwidthLog.window_start).label('hour'),
                  func.sum(BandwidthLog.bytes_sent).label('bytes_sent'),
                  func.sum(BandwidthLog.bytes_received).label('bytes_received'))
              .group_by(BandwidthLog.mac, func.strftime('%Y-%m-%d %H', BandwidthLog.window_start))
              .order_by(func.strftime('%Y-%m-%d %H', BandwidthLog.window_start).desc())
              .limit(200).all())
    # Daily rollups
    daily = (db.session.query(BandwidthLog.mac,
                 func.strftime('%Y-%m-%d', BandwidthLog.window_start).label('day'),
                 func.sum(BandwidthLog.bytes_sent).label('bytes_sent'),
                 func.sum(BandwidthLog.bytes_received).label('bytes_received'))
             .group_by(BandwidthLog.mac, func.strftime('%Y-%m-%d', BandwidthLog.window_start))
             .order_by(func.strftime('%Y-%m-%d', BandwidthLog.window_start).desc())
             .limit(100).all())
    return render_template("admin_bandwidth_report.html", hourly=hourly, daily=daily)


# --- CSV Exports -------------------------------------------------------------

@main.route("/admin/export/forensic")
@admin_required
def export_forensic():
    """Export forensic log as CSV."""
    import csv
    import io
    from flask import Response

    log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "..", "logs", "forensic.log")
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["timestamp", "mac", "action", "detail"])
    if os.path.exists(log_path):
        with open(log_path, "r") as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    writer.writerow([entry.get("timestamp"), entry.get("mac"),
                                     entry.get("action"), json.dumps(entry.get("detail"))])
                except Exception:
                    pass
    output.seek(0)
    return Response(output.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=forensic_log.csv"})


@main.route("/admin/export/dns")
@admin_required
def export_dns():
    """Export DNSLog as CSV."""
    import csv
    import io
    from flask import Response

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "mac", "domain", "timestamp", "flagged"])
    for log in DNSLog.query.order_by(DNSLog.timestamp.desc()).all():
        writer.writerow([log.id, log.mac, log.domain, log.timestamp, log.flagged])
    output.seek(0)
    return Response(output.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=dns_log.csv"})


@main.route("/admin/export/bans")
@admin_required
def export_bans():
    """Export Ban history as CSV."""
    import csv
    import io
    from flask import Response

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "mac", "reason", "risk_score_at_ban", "since", "active", "unbanned_at"])
    for ban in Ban.query.order_by(Ban.since.desc()).all():
        writer.writerow([ban.id, ban.mac, ban.reason, ban.risk_score_at_ban,
                         ban.since, ban.active, ban.unbanned_at])
    output.seek(0)
    return Response(output.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=ban_history.csv"})


@main.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("main.login"))
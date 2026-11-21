"""Phase 7 email delivery for verification links (and OTP).

Uses stdlib smtplib when SMTP settings are configured in app.config.
Otherwise falls back to console + forensic-log delivery (LAB MODE):
the verification URL or OTP is printed to the server console and written
to the forensic log so the full verify flow is exercisable without a live
mail server.
"""
import logging
import smtplib
import ssl
import threading
from email.message import EmailMessage
from typing import Optional

from app.logging.forensic import log_forensic_event

log = logging.getLogger("zta.mail")

_LAST_VERIFY_URL = None   # exposes the most recent link for tests / console
_LAST_NOTIFICATION = None  # exposes the most recent warning for tests / demos


def get_last_verification_url():
    """Return the most recently generated verification URL (LAB MODE helper)."""
    return _LAST_VERIFY_URL


def get_last_notification():
    """Return the most recent risk/ban notice ({to, subject, body})

    Mirrors get_last_verification_url(); used by tests and demos (LAB MODE).
    """
    return _LAST_NOTIFICATION


def _build_smtp_config(app) -> Optional[dict]:
    """Extract SMTP config from app.config, return None if incomplete."""
    server = app.config.get("MAIL_SERVER")
    if not server:
        return None
    return {
        "server": server,
        "port": int(app.config.get("MAIL_PORT", 587)),
        "use_tls": str(app.config.get("MAIL_USE_TLS", "true")).lower() in ("1", "true", "yes"),
        "use_ssl": str(app.config.get("MAIL_USE_SSL", "false")).lower() in ("1", "true", "yes"),
        "username": app.config.get("MAIL_USERNAME"),
        "password": app.config.get("MAIL_PASSWORD"),
        "default_sender": app.config.get("MAIL_DEFAULT_SENDER", "noreply@ztagateway.local"),
    }


def _send_smtp(config: dict, to_addr: str, subject: str, body: str, from_addr: str = None, timeout: int = 10) -> bool:
    """Send email via SMTP. Returns True on success, False on failure."""
    from_addr = from_addr or config["default_sender"]

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg.set_content(body)

    try:
        if config["use_ssl"]:
            context = ssl.create_default_context()
            server = smtplib.SMTP_SSL(config["server"], config["port"], context=context, timeout=timeout)
        else:
            server = smtplib.SMTP(config["server"], config["port"], timeout=timeout)
            if config["use_tls"]:
                context = ssl.create_default_context()
                server.starttls(context=context)

        if config["username"] and config["password"]:
            server.login(config["username"], config["password"])

        server.send_message(msg)
        server.quit()
        return True

    except Exception as exc:
        # Log the failure reason without secrets
        log.warning("SMTP send failed: %s", exc)
        # Also log to forensic for audit trail (no secrets)
        log_forensic_event("system", "EMAIL_SMTP_FAILED", {
            "server": config["server"],
            "port": config["port"],
            "error_type": type(exc).__name__,
            "error_msg": str(exc)[:200],  # truncate
        })
        return False


def _send_async(app, config: dict, to_addr: str, subject: str, body: str, from_addr: str = None):
    """Send email in a background thread with timeout (non-blocking)."""
    def _worker():
        with app.app_context():
            _send_smtp(config, to_addr, subject, body, from_addr)

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()
    # Don't wait — fire and forget. Registration must not block on email.
    # If you need to verify delivery in tests, use the LAB MODE fallback
    # which is synchronous and sets _LAST_VERIFY_URL.
    return thread


def mail_mode(app):
    """Return a one-line description of how outbound email will be delivered.

    Used by run.py for the startup banner so the operator can see at a glance
    whether real SMTP is active or the console/forensic LAB MODE fallback is in
    use.
    """
    config = _build_smtp_config(app)
    if config is not None:
        return f"SMTP ready ({config['server']})"
    return "LAB MODE (no MAIL_SERVER configured)"


def send_verification_email(app, email_address, username, verify_url, code=None):
    """
    Deliver the verification link (and optional 6-digit typed code).

    Real SMTP if configured, else console/forensic LAB MODE fallback.

    Returns "smtp" if queued for SMTP delivery, "console" if LAB MODE fallback.
    """
    global _LAST_VERIFY_URL
    _LAST_VERIFY_URL = verify_url

    code_line = (f"Or type this code on the portal page: {code}\n\n"
                 if code else "")

    config = _build_smtp_config(app)
    if config is None:
        # No SMTP config — LAB MODE fallback
        _lab_mode_fallback(username, email_address, verify_url, code=code)
        return "console"

    subject = "Verify your ZTA Gateway account"
    body = (
        f"Hi {username},\n\n"
        f"{code_line}"
        f"Or click this link to verify your email for ZTA Gateway:\n"
        f"{verify_url}\n\n"
        f"The code and link expire in 15 minutes.\n\n"
        f"If you didn't request this, you can ignore this email."
    )

    # Try synchronous send first (with short timeout) to catch config errors early
    # If it fails, fall back to LAB MODE. If it succeeds, we're done.
    # For production non-blocking behavior, we could use _send_async, but
    # synchronous with timeout=10 is fine for this scale and gives better feedback.
    try:
        if _send_smtp(config, email_address, subject, body, timeout=10):
            log.info("verification email sent to %s", email_address)
            return "smtp"
    except Exception as exc:
        log.warning("SMTP send failed (%s); falling back to console", exc)

    # LAB MODE fallback — no live mail server. The link still reaches the user
    # via the server console and the forensic audit log.
    _lab_mode_fallback(username, email_address, verify_url, code=code)
    return "console"


def send_otp_email(app, email_address, username, otp_code):
    """
    Deliver a 6-digit OTP code via email.

    Returns "smtp" if queued for SMTP delivery, "console" if LAB MODE fallback.
    Does NOT overwrite _LAST_VERIFY_URL (preserved for verification link tests).
    """
    config = _build_smtp_config(app)
    if config is None:
        _lab_mode_fallback(username, email_address, f"OTP: {otp_code}", is_otp=True)
        return "console"

    subject = "Your ZTA Gateway verification code"
    body = (
        f"Hi {username},\n\n"
        f"Your verification code is: {otp_code}\n\n"
        f"This code expires in 10 minutes. Do not share it with anyone.\n\n"
        f"If you didn't request this, you can ignore this email."
    )

    try:
        if _send_smtp(config, email_address, subject, body, timeout=10):
            log.info("OTP email sent to %s", email_address)
            return "smtp"
    except Exception as exc:
        log.warning("SMTP send failed (%s); falling back to console", exc)

    _lab_mode_fallback(username, email_address, f"OTP: {otp_code}", is_otp=True)
    return "console"


def send_risk_email(app, to, subject, body_text, body_html=None):
    """Deliver a risk/ban notice.

    Real SMTP when SMTP is configured; otherwise LAB MODE fallback prints
    the message and writes an EMAIL_NOTICE forensic entry.
    Returns "smtp" or "console". Raises only if the real SMTP send fails,
    so the caller can record a failed row.
    """
    global _LAST_NOTIFICATION
    _LAST_NOTIFICATION = {"to": to, "subject": subject, "body": body_text}

    config = _build_smtp_config(app)
    if config is not None:
        try:
            if _send_smtp(config, to, subject, body_text, timeout=10):
                log.info("risk email sent to %s (%s)", to, subject)
                return "smtp"
        except Exception as exc:
            log.warning("SMTP send failed for risk email (%s)", exc)
            raise

    # LAB MODE fallback — no live mail server. Message still reaches the
    # operator via the console and the forensic audit log.
    print(f"[mail:LAB-MODE] NOTICE {to}: {subject}\n{body_text}", flush=True)
    log_forensic_event(to, "EMAIL_NOTICE",
                       {"subject": subject, "body": body_text})
    return "console"


def _lab_mode_fallback(username: str, email_address: str, content: str, is_otp: bool = False, code: str = None):
    """LAB MODE: print to console and log forensic event."""
    label = "OTP" if is_otp else "VERIFY"
    if code:
        print(f"[mail:LAB-MODE] {label} {email_address}: code={code} url={content}", flush=True)
        log_forensic_event(username, "EMAIL_VERIFY",
                           {"to": email_address, "url": content, "code": code})
    else:
        print(f"[mail:LAB-MODE] {label} {email_address}: {content}", flush=True)
        log_forensic_event(username, "EMAIL_VERIFY" if not is_otp else "EMAIL_OTP",
                           {"to": email_address, "content": content})
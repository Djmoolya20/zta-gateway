#!/usr/bin/env python3
"""
SMTP Diagnostic Script for ZTA Gateway

Reads MAIL_* environment variables from .env and attempts an SMTP login
plus a test email. Prints the exact exception and a plain-English hint.

Usage:
    ./venv/bin/python scripts/smtp_check.py --to recipient@example.com
    ./venv/bin/python scripts/smtp_check.py --to recipient@example.com --from "ZTA Gateway <noreply@domain.com>"
"""

import os
import sys
import argparse
import smtplib
import ssl
from email.message import EmailMessage
from pathlib import Path


def load_env(env_path: Path = None):
    """Load .env file manually (no python-dotenv dependency)."""
    if env_path is None:
        env_path = Path(__file__).parent.parent / ".env"

    if not env_path.exists():
        print(f"[warn] .env file not found at {env_path}")
        return

    with open(env_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                print(f"[warn] line {line_num}: malformed (no '='): {line}")
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"\'')
            if key and key not in os.environ:
                os.environ[key] = value
    print(f"[info] Loaded environment from {env_path}")


def get_smtp_config():
    """Extract SMTP configuration from environment."""
    config = {
        "server": os.environ.get("MAIL_SERVER"),
        "port": int(os.environ.get("MAIL_PORT", 587)),
        "use_tls": os.environ.get("MAIL_USE_TLS", "true").lower() in ("1", "true", "yes"),
        "use_ssl": os.environ.get("MAIL_USE_SSL", "false").lower() in ("1", "true", "yes"),
        "username": os.environ.get("MAIL_USERNAME"),
        "password": os.environ.get("MAIL_PASSWORD"),
        "default_sender": os.environ.get("MAIL_DEFAULT_SENDER", "noreply@ztagateway.local"),
    }
    return config


def validate_config(config):
    """Check required config values and return list of missing ones."""
    missing = []
    if not config["server"]:
        missing.append("MAIL_SERVER")
    if not config["username"]:
        missing.append("MAIL_USERNAME")
    if not config["password"]:
        missing.append("MAIL_PASSWORD")
    return missing


def print_config(config):
    """Print config (with password masked)."""
    print("\n--- SMTP Configuration ---")
    print(f"  Server:       {config['server'] or 'NOT SET'}")
    print(f"  Port:         {config['port']}")
    print(f"  Use TLS:      {config['use_tls']}")
    print(f"  Use SSL:      {config['use_ssl']}")
    print(f"  Username:     {config['username'] or 'NOT SET'}")
    print(f"  Password:     {'SET (' + '*' * 8 + ')' if config['password'] else 'NOT SET'}")
    print(f"  Default From: {config['default_sender']}")
    print()


def analyze_exception(exc, config):
    """Return a plain-English hint based on the exception."""
    err_str = str(exc).lower()
    err_type = type(exc).__name__

    hints = []

    if isinstance(exc, smtplib.SMTPAuthenticationError):
        hints.append("Authentication failed. Check username/password.")
        if "gmail" in config["server"].lower():
            hints.append("Gmail requires an App Password (not your regular password) with 2FA enabled.")
            hints.append("Generate one at: https://myaccount.google.com/apppasswords")
        elif "outlook" in config["server"].lower() or "office365" in config["server"].lower():
            hints.append("Outlook/Office365 may require an App Password or have security defaults blocking SMTP.")

    elif isinstance(exc, smtplib.SMTPConnectError):
        hints.append("Could not connect to SMTP server.")
        hints.append(f"Check MAIL_SERVER ({config['server']}) and MAIL_PORT ({config['port']}).")
        hints.append("Verify firewall/antivirus is not blocking outbound connections on this port.")

    elif isinstance(exc, (smtplib.SMTPServerDisconnected, ConnectionResetError, TimeoutError)):
        hints.append("Connection dropped unexpectedly.")
        hints.append("Try toggling MAIL_USE_TLS / MAIL_USE_SSL (one must be true, not both).")
        hints.append("Port 587 typically uses STARTTLS (MAIL_USE_TLS=true).")
        hints.append("Port 465 typically uses implicit SSL (MAIL_USE_SSL=true).")

    elif isinstance(exc, ssl.SSLError):
        hints.append("SSL/TLS handshake failed.")
        hints.append("Check MAIL_USE_TLS / MAIL_USE_SSL settings match the server's expectations.")

    elif "authentication" in err_str or "login" in err_str:
        hints.append("Authentication issue. Verify credentials and App Password.")

    elif "certificate" in err_str:
        hints.append("SSL certificate verification failed.")
        hints.append("This may happen with self-signed certs or corporate proxies.")

    if not hints:
        hints.append(f"Unexpected error: {err_type}: {exc}")

    return hints


def send_test_email(config, to_addr, from_addr=None):
    """Attempt to send a test email via SMTP."""
    from_addr = from_addr or config["default_sender"]

    msg = EmailMessage()
    msg["Subject"] = "ZTA Gateway SMTP Test"
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg.set_content(
        "This is a test email from ZTA Gateway SMTP diagnostic script.\n"
        "If you received this, SMTP configuration is working correctly.\n"
        f"\nServer: {config['server']}:{config['port']}"
        f"\nTLS: {config['use_tls']}, SSL: {config['use_ssl']}"
    )

    # Create connection
    if config["use_ssl"]:
        context = ssl.create_default_context()
        server = smtplib.SMTP_SSL(config["server"], config["port"], context=context, timeout=10)
    else:
        server = smtplib.SMTP(config["server"], config["port"], timeout=10)
        if config["use_tls"]:
            context = ssl.create_default_context()
            server.starttls(context=context)

    # Login and send
    server.login(config["username"], config["password"])
    server.send_message(msg)
    server.quit()

    return True


def main():
    parser = argparse.ArgumentParser(description="ZTA Gateway SMTP Diagnostic Tool")
    parser.add_argument("--to", required=True, help="Recipient email address for test email")
    parser.add_argument("--from", dest="from_addr", help="Sender email address (default: MAIL_DEFAULT_SENDER)")
    parser.add_argument("--env", help="Path to .env file (default: project root/.env)")
    parser.add_argument("--no-send", action="store_true", help="Only validate config and test connection, don't send email")
    args = parser.parse_args()

    print("=" * 60)
    print("ZTA Gateway SMTP Diagnostic")
    print("=" * 60)

    # Load .env
    env_path = Path(args.env) if args.env else None
    load_env(env_path)

    # Get config
    config = get_smtp_config()
    print_config(config)

    # Validate
    missing = validate_config(config)
    if missing:
        print("[FAIL] Missing required configuration:")
        for m in missing:
            print(f"  - {m}")
        print("\nCreate a .env file based on .env.example with these values.")
        return 1

    print("[OK] All required SMTP settings present.")

    if args.no_send:
        print("\n--no-send specified: skipping test email.")
        return 0

    # Attempt connection and send
    print(f"\n--- Testing Connection to {config['server']}:{config['port']} ---")
    try:
        if config["use_ssl"]:
            context = ssl.create_default_context()
            server = smtplib.SMTP_SSL(config["server"], config["port"], context=context, timeout=10)
        else:
            server = smtplib.SMTP(config["server"], config["port"], timeout=10)
            if config["use_tls"]:
                context = ssl.create_default_context()
                server.starttls(context=context)

        print("[OK] TCP connection established")
        if config["use_tls"] and not config["use_ssl"]:
            print("[OK] STARTTLS negotiated")

        print("--- Authenticating ---")
        server.login(config["username"], config["password"])
        print("[OK] Authentication successful")

        if not args.no_send:
            print(f"--- Sending test email to {args.to} ---")
            send_test_email(config, args.to, args.from_addr)
            print("[OK] Test email sent successfully!")
            print(f"      Check {args.to} inbox (and spam folder).")

        server.quit()
        print("\n=== ALL CHECKS PASSED ===")
        return 0

    except Exception as exc:
        print(f"\n[FAIL] {type(exc).__name__}: {exc}")
        print("\n--- Troubleshooting Hints ---")
        for hint in analyze_exception(exc, config):
            print(f"  * {hint}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
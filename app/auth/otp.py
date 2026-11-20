"""OTP utilities for email verification.

Uses stdlib only: secrets for generation, hashlib for hashing.
No external dependencies.
"""
import hashlib
import hmac
import secrets
import time
from datetime import datetime, timedelta


OTP_LENGTH = 6
OTP_EXPIRY_MINUTES = 10
OTP_MAX_ATTEMPTS = 5
OTP_RESEND_COOLDOWN_SECONDS = 60


def generate_otp() -> str:
    """Generate a 6-digit OTP using cryptographically secure random."""
    return "".join(str(secrets.randbelow(10)) for _ in range(OTP_LENGTH))


def hash_otp(otp: str) -> str:
    """
    Hash an OTP using PBKDF2-HMAC-SHA256 with a random salt.
    Returns: salt:hash (hex encoded)
    """
    salt = secrets.token_bytes(16)
    hash_val = hashlib.pbkdf2_hmac("sha256", otp.encode(), salt, 100_000)
    return salt.hex() + ":" + hash_val.hex()


def verify_otp(otp: str, otp_hash: str) -> bool:
    """
    Verify an OTP against its hash using constant-time comparison.
    """
    try:
        salt_hex, hash_hex = otp_hash.split(":", 1)
        salt = bytes.fromhex(salt_hex)
        expected_hash = bytes.fromhex(hash_hex)
        computed_hash = hashlib.pbkdf2_hmac("sha256", otp.encode(), salt, 100_000)
        return hmac.compare_digest(computed_hash, expected_hash)
    except Exception:
        return False


def is_otp_valid(user) -> bool:
    """Check if user's OTP is still valid (not expired, attempts not exceeded)."""
    if not user.otp_hash or not user.otp_expires_at:
        return False
    if datetime.utcnow() > user.otp_expires_at:
        return False
    if user.otp_attempts >= OTP_MAX_ATTEMPTS:
        return False
    return True


def can_resend_otp(user) -> bool:
    """Check if enough time has passed since last OTP send (60s cooldown)."""
    if not user.otp_last_sent:
        return True
    elapsed = (datetime.utcnow() - user.otp_last_sent).total_seconds()
    return elapsed >= OTP_RESEND_COOLDOWN_SECONDS


def set_otp(user, otp: str):
    """Store OTP hash and metadata on user object."""
    user.otp_hash = hash_otp(otp)
    user.otp_expires_at = datetime.utcnow() + timedelta(minutes=OTP_EXPIRY_MINUTES)
    user.otp_attempts = 0
    user.otp_last_sent = datetime.utcnow()


def clear_otp(user):
    """Clear OTP fields after successful verification."""
    user.otp_hash = None
    user.otp_expires_at = None
    user.otp_attempts = 0
    user.otp_last_sent = None


def increment_otp_attempts(user):
    """Increment OTP attempt counter."""
    user.otp_attempts += 1
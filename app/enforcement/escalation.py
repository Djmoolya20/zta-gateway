"""Phase 7 escalation: repeat offenders are banned at a lower threshold.

Zero-trust corollary — an unban resets a device's *state* to unknown, but
the network does not forget that it misbehaved before.  The effective ban
threshold drops with each prior ban, **but only if the ban occurred within
the rolling reset window** — after that the penalty decays, so a device
can rebuild trust through sustained good behaviour.
"""

from datetime import datetime, timedelta

from app import config as cfg

from app import config as cfg

# ---------------------------------------------------------------------------
# Config (imported from *app*.config as *cfg*)
# ---------------------------------------------------------------------------
# How many seconds back a ban is considered "recent".  After this window
# of clean behaviour the multiplier resets to 1.0 (full threshold).
# Default 7 days = 604 800 s; for a quick demo set
#   ZTA_ESCALATION_RESET_SECONDS=120   (2 minutes).
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
def get_escalation_multiplier(mac) -> float:
    """Return the threshold multiplier for *mac* based on *recent* prior bans.

    Only bans whose ``since`` timestamp falls within the most recent
    ``cfg.ESCALATION_RESET_SECONDS`` are counted.

    ``prior bans``:
        0        → 1.00  (full threshold)
        1        → 0.75  (reduced threshold)
        2+       → 0.50  (strongly reduced threshold)
    ---------------------------------------------------------------------------
    """
    from app.models import Ban

    cutoff = datetime.utcnow() - timedelta(seconds=cfg.ESCALATION_RESET_SECONDS)
    recent_bans = Ban.query.filter(Ban.mac == mac, Ban.since >= cutoff).count()

    if recent_bans >= 2:
        return 0.5
    if recent_bans == 1:
        return 0.75
    return 1.0


def effective_ban_threshold(base_threshold: int, mac: str) -> float:
    """Base threshold adjusted by prior-ban history for ``mac``."""
    return base_threshold * get_escalation_multiplier(mac)


def get_trust_status(mac) -> str:
    """Human‑readable trust status for the dashboard.

    "Elevated scrutiny"   — 2+ recent bans (threshold halved)
    "Under watch"         — 1 recent ban  (threshold 75 %)
    "Normal trust"        — no recent bans (full threshold)
    """
    mult = get_escalation_multiplier(mac)
    if mult <= 0.5:
        return "Elevated scrutiny (2+ recent violations)"
    if mult <= 0.75:
        return "Under watch (1 recent violation)"
    return "Normal trust"


def explain_risk(identity: int, device: int, network: int, behavior: int,
                 flagged_domains: list) -> str:
    """Human‑readable "Why was this flagged?" explanation.

    Maps the four per‑dimension scores (0‑100) and the list of blocklisted
    domains that were seen into a short plain‑English sentence that an admin
    can read on the ban toast / dashboard instead of a raw composite number.

    Heuristics (tuneable):
      identity >= 50  → "multiple failed login attempts detected"
      device   >= 50  → "device is new/unapproved"
      network  >= 40  → "contacted flagged domain(s): {domains}"
      behavior >= 50  → "traffic pattern deviates significantly from this
                        device's normal baseline"
    Returns the first matching reason, or "no significant anomalies" if
    nothing crosses its threshold.
    """
    reasons: list[str] = []

    if identity >= 50:
        reasons.append("multiple failed login attempts detected")
    if device >= 50:
        reasons.append("device is new/unapproved")
    if network >= 40:
        # only emit the domain list if we actually have flagged ones
        bad = [d for d in flagged_domains if d]
        if bad:
            reasons.append(f"contacted flagged domain(s): {', '.join(bad)}")
        elif network >= 40:
            # still above threshold even without blocklisted names
            reasons.append("suspicious network activity")
    if behavior >= 50:
        reasons.append("traffic pattern deviates significantly from this device's normal baseline")

    if not reasons:
        return "no significant anomalies"
    # Return the first strong reason; could be combined later.
    return "; ".join(reasons)
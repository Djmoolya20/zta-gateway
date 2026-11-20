# ZTA Gateway — Differentiators & Practical Scenarios

## Executive Summary

ZTA Gateway is **not** a traditional firewall, consumer router, or Pi-hole. It is a **Zero Trust Network Access (ZTNA) gateway** that implements adaptive, per-device behavioral baselines with four-dimensional composite risk scoring — a combination not found in conventional network security tools.

---

## Comparison with Existing Solutions

| Feature | ZTA Gateway | Traditional Firewall | Consumer Router | Pi-hole |
|---------|-------------|---------------------|-----------------|---------|
| **Per-device adaptive baseline (Welford online algorithm)** | ✅ | ❌ | ❌ | ❌ |
| **4-dimension composite risk (Identity, Device, Network, Behavior)** | ✅ | ❌ | ❌ | ❌ |
| **Identity risk (failed login tracking)** | ✅ | ❌ | ❌ | ❌ |
| **Device risk (approval status + age)** | ✅ | ❌ | ❌ | ❌ |
| **Network risk (blocklist + suspicious ports)** | ✅ | Partial (static rules) | ❌ | DNS only |
| **Behavior risk (z-score vs own baseline)** | ✅ | ❌ | ❌ | ❌ |
| **Zero-trust unban reset (re-earn trust)** | ✅ | ❌ | ❌ | ❌ |
| **Repeat-offender escalation (lower threshold)** | ✅ | ❌ | ❌ | ❌ |
| **Threat traceback (RiskHistory timeline)** | ✅ | ❌ | ❌ | ❌ |
| **Explainable scores (sub-scores + weights)** | ✅ | ❌ | ❌ | ❌ |
| **Captive portal for unapproved devices** | ✅ | ❌ | ❌ | ❌ |
| **DNS audit trail + bandwidth tracking** | ✅ | Partial | ❌ | ✅ (DNS only) |
| **Self-registration + admin approval workflow** | ✅ | ❌ | ❌ | ❌ |
| **OTP + link email verification** | ✅ | ❌ | ❌ | ❌ |
| **Forensic JSON log (independent of DB)** | ✅ | ❌ | ❌ | ❌ |

---

## What Makes ZTA Gateway Unique

### 1. Per-Device Adaptive Behavioral Baseline (Welford)
Unlike firewalls that use global thresholds, ZTA Gateway learns each device's "normal" traffic patterns (packet count, byte count, unique flows, DNS queries) using **Welford's online algorithm** — O(1) memory, no raw history stored. A streaming 4K TV and a laptop have completely different baselines; both are scored against *their own* normal.

### 2. Four-Dimension Composite Risk
Risk is not a single number — it's a **weighted composite** of four independent dimensions:
- **Identity (20%)**: Failed login attempts from the device's IP
- **Device (20%)**: Approval status and age
- **Network (25%)**: Blocklisted domains + suspicious ports
- **Behavior (35%)**: Deviation from learned baseline (z-score)

Each dimension is visible in the dashboard — admins see *why* a device scored HIGH.

### 3. Zero-Trust Unban Reset
When an admin unbans a device, it **does not** return to "approved." It resets to `unknown` and must re-earn trust. This prevents "unban and forget" workflows.

### 4. Repeat-Offender Escalation
Devices with prior bans face progressively lower ban thresholds:
- 0 prior bans: 1.0× (base 70)
- 1 prior ban: 0.75× (52.5)
- 2+ prior bans: 0.5× (35.0)

Proven in integration test: a repeat attack at total 65 (below base 70) triggered a ban at the escalated 52.5 threshold.

### 5. Threat Traceback (RiskHistory Timeline)
Every 30-second scoring window writes a `RiskHistory` row. The traceback view shows:
- First anomaly (when score first reached MEDIUM+)
- Escalation path (composite scores over time)
- Final action (ban event)
- Per-window sub-score breakdown

### 6. Explainable Scores
The dashboard and drill-down views show each sub-score, its weight, and its contribution to the total. Admins don't just see "HIGH" — they see *Identity 75 (×0.20=15.0), Network 80 (×0.25=20.0), Behavior 43 (×0.35=15.0) = 50 → MEDIUM*.

### 7. Captive Portal at Application Layer
Unapproved devices (status ≠ `approved`) are gated at the login page for any non-whitelisted path. Whitelisted: `/login`, `/register`, `/verify`, `/verify-otp`, `/logout`, `/admin`, `/static`. True network-level DNS-hijack captive portal is documented as future work.

### 8. DNS Audit Trail + Bandwidth Tracking
Every DNS query per device per window is logged (`DNSLog`) with blocklist flag. Bandwidth per 30s window (`BandwidthLog`) enables hourly/daily rollups. Neither requires external SIEM.

### 9. Self-Registration with Admin Approval + OTP Verification
Users register → pending → email verification (OTP + link fallback) → admin approval → login. Rate-limited, with metadata capture (IP, user-agent, claimed device).

---

## Practical Scenarios

### Scenario 1: Home Network with IoT Devices
**Devices**: Smart TV, thermostat, cameras, phones, laptops
**Admin sees**:
- IoT devices (TV, thermostat) learn baselines quickly — steady LOW scores
- Unknown phone connects → status `unknown`, auto-approved for Phase 1, baseline learning starts
- Teenager's laptop does port sweep → Behavior spikes → HIGH → auto-ban at threshold 70
- Admin views traceback: sees escalation path, flagged domains, exact window of anomaly
- Unbans laptop → resets to `unknown` → must re-earn trust
- Repeat sweep next week → banned at 52.5 (escalated threshold)

**Value**: No manual rule writing. IoT devices don't trigger false positives because their baseline adapts.

### Scenario 2: Small Office / Clinic (BYOD, HIPAA Concern)
**Devices**: Staff laptops, personal phones, medical IoT, guest Wi-Fi
**Admin sees**:
- Failed login attempts on admin portal → Identity risk climbs (visible in dashboard)
- Staff laptop queries blocklisted domain (telemetry, ads) → Network risk flags
- Medical device (approved, static IP) stays LOW — baseline learns its predictable pattern
- Guest phone on Wi-Fi → captive portal redirects to login → admin approves or rejects
- CSV exports for forensic log, DNS queries, ban history — audit-ready

**Value**: Identity dimension catches credential stuffing. Network dimension catches data exfiltration domains. Explainable scores help demonstrate compliance posture.

### Scenario 3: Hostel / University Lab Network (High Churn)
**Devices**: Hundreds of student devices, high turnover
**Admin sees**:
- Pending approvals queue with registration IP, claimed MAC, timestamp
- Auto-ban catches port scanners and malware-infected laptops
- Repeat offenders (students testing tools) hit escalated thresholds
- Bandwidth report shows heavy users per hour/day
- Top domains report shows most-queried domains (flagged highlighted)
- 10-second auto-refresh keeps dashboard live during incidents

**Value**: Scales to high-churn environments. Rate limiting prevents registration spam. Escalation handles repeat offenders automatically.

---

## Honest Limitations (Documented in CLAUDE.md)

| Limitation | Impact | Mitigation / Future Work |
|------------|--------|--------------------------|
| **Boiling frog**: Baseline updates during attack windows | Slow sustained attack can "train in" | Freeze baseline updates during HIGH-risk windows; trimmed/weighted estimates |
| **DNS cache blind spot**: OS DNS cache serves blocklisted domains without packet capture | Blocklisted domains missed if cached | Force uncached queries (random subdomains) for testing; document limitation |
| **ARP quarantine recorded-only on Windows** | No true wire isolation on Windows | Option B daemon logs quarantine; true isolation demoable on Linux VM |
| **Wi-Fi AP passthrough limits visibility** | Only sees traffic to/from gateway | Deploy as inline gateway or on managed switch span port |
| **No TLS inspection** | Encrypted payloads invisible | SNI-based risk (future); MITRE ATT&CK tagging (future) |
| **Single gateway** | No federation | Multi-gateway sync (future) |

---

## Suggested Larger Features (Not Implemented)

1. **Network-level captive portal** — DNS hijack for *any* hostname → portal page (requires dnsmasq/Unbound integration)
2. **MITRE ATT&CK tagging** — Map flagged domains/ports to tactics/techniques in traceback
3. **SIEM integration** — Syslog forwarder, Elastic/OpenSearch connector
4. **Multi-gateway federation** — Shared blocklists, baselines, ban sync across sites
5. **TLS SNI inspection** — Extract SNI from ClientHello for network risk without MITM
6. **Device fingerprinting** — JA3/JA3S, DHCP fingerprints for device risk dimension
7. **Alerting/notification** — Email/Slack/webhook on HIGH risk, ban events
8. **Historical reporting** — Daily/weekly risk summaries, trend analysis API

---

## Conclusion

ZTA Gateway fills a gap between **consumer tools** (Pi-hole, router firewalls) and **enterprise ZTNA platforms** (Zscaler, Cloudflare Access, Twingate). It brings adaptive per-device baselines, explainable multi-dimension risk, zero-trust enforcement, and forensic traceability to a self-hostable, open-codebase package — with honest documentation of where it falls short of enterprise-grade solutions.
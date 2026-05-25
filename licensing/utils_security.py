import hmac
import hashlib
from dataclasses import dataclass
from typing import Optional

from django.conf import settings
from django.utils import timezone

from .models import ValidationLog, Device


@dataclass
class CloneDecision:
    suspected: bool
    reason: str
    locked: bool


def verify_hmac(secret: str, serial: str, mac: str, ts: int, nonce: str, signature_hex: str) -> bool:
    canonical = f"{serial}|{mac}|{ts}|{nonce}"
    expected = hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_hex)


def clone_detect_and_lock(device: Device, ip: Optional[str], mac: str, nonce: str) -> CloneDecision:
    # defaults if not set in settings.py
    window_sec = int(getattr(settings, "LICENSE_CLONE_WINDOW_SECONDS", 3600))  # 1 hour
    max_ips = int(getattr(settings, "LICENSE_CLONE_MAX_IPS_IN_WINDOW", 2))
    lock_minutes = int(getattr(settings, "LICENSE_AUTO_LOCKOUT_MINUTES", 120))

    now = timezone.now()
    since = now - timezone.timedelta(seconds=window_sec)

    # 1) MAC mismatch is the strongest signal
    mac_mismatch = (device.mac_address or "").lower() != (mac or "").lower()

    # 2) Too many different IPs in a short window
    ip_count = (
        ValidationLog.objects.filter(device=device, timestamp__gte=since)
        .exclude(ip__isnull=True)
        .values("ip").distinct().count()
    )

    # 3) Too many different MACs seen recently
    mac_count = (
        ValidationLog.objects.filter(device=device, timestamp__gte=since)
        .exclude(mac_address="")
        .values("mac_address").distinct().count()
    )

    suspected = mac_mismatch or ip_count > max_ips or mac_count > 1
    reasons = []
    if mac_mismatch:
        reasons.append("mac_mismatch")
    if ip_count > max_ips:
        reasons.append(f"too_many_ips:{ip_count}")
    if mac_count > 1:
        reasons.append(f"multiple_macs:{mac_count}")

    locked = False
    if suspected:
        device.clone_score = min(device.clone_score + 1, 100)
        device.lock_status = device.LockStatus.CLONE_SUSPECTED
        device.lock_reason = ",".join(reasons)

        # lock aggressively on MAC mismatch OR repeated suspicion
        if mac_mismatch or device.clone_score >= 3:
            device.lock_status = device.LockStatus.LOCKED
            device.lock_reason = "auto_lockout:" + ",".join(reasons)
            device.lock_until = now + timezone.timedelta(minutes=lock_minutes)
            locked = True

        device.save(update_fields=["clone_score", "lock_status", "lock_reason", "lock_until"])

    return CloneDecision(suspected=suspected, reason=",".join(reasons), locked=locked)

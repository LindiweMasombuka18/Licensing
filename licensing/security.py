import hmac
import hashlib
from datetime import timedelta

from django.utils import timezone


def build_signing_message(device_uid, serial_number, mac_address, nonce, timestamp):
    """
    - Each value is added to a list.
    - `or ""` means if the value is None, replace it with an empty string.
    """
    parts = [
        device_uid or "",
        serial_number or "",
        mac_address or "",
        nonce or "",
        timestamp or "",
    ]
    return "|".join(parts)  # This list becomes one long string


def sign_message(secret, message):
    """
    hmac.new() creates a secure signature.

    .hexdigest() converts the final result to a readable hex string like:
    a93f0ebf9c032abc1296ff129830...
    """
    return hmac.new(
        key=secret.encode("utf-8"),  # Convert secret string → bytes
        msg=message.encode("utf-8"),  # Convert message string → bytes
        digestmod=hashlib.sha256,  # Use SHA256 hash algorithm
    ).hexdigest()


def constant_time_compare(a, b):
    # a or "" ensures None becomes an empty string instead of crashing
    return hmac.compare_digest(a or "", b or "")


def timestamp_is_fresh(timestamp_str, max_age_seconds=300):
    """
    Checks if the timestamp is still fresh (not older than max_age_seconds)
    """
    try:
        ts = timezone.datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
    except Exception:
        return False

    if timezone.is_naive(ts):
        ts = timezone.make_aware(ts, timezone.utc)

    now = timezone.now()
    delta = abs((now - ts).total_seconds())
    return delta <= max_age_seconds

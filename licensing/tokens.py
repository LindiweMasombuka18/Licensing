import uuid
import jwt

from django.conf import settings
from django.utils import timezone


def issue_grant_token(*, device, subscription, bundle_snapshot, ttl_hours=None):
    now = timezone.now()
    ttl = ttl_hours or settings.LICENSE_GRANT_TTL_HOURS
    expires_at = now + timezone.timedelta(hours=ttl)
    jti = str(uuid.uuid4())

    payload = {
        "jti": jti,
        "sub": str(subscription.id),
        "device_id": str(device.id),
        "device_uid": device.device_uid,
        "customer_id": str(device.customer_id),
        "subscription_status": subscription.computed_status(),
        "bundle_name": subscription.bundle.name,
        "features": bundle_snapshot,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
    }

    token = jwt.encode(
        payload,
        settings.LICENSE_GRANT_SECRET,
        algorithm=settings.LICENSE_GRANT_ALGORITHM,
    )

    return {
        "jti": jti,
        "token": token,
        "issued_at": now,
        "expires_at": expires_at,
        "payload": payload,
    }

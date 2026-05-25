import uuid
import jwt
from datetime import timedelta

from django.conf import settings
from django.utils import timezone
from rest_framework.decorators import api_view
from rest_framework.response import Response

from .models import Device, DeviceLicense


TOKEN_TTL_SECONDS = 4 * 60 * 60  # 4 hours


def _build_features(bundle, override_policy=None):
    features = bundle.feature_snapshot()

    # Apply per-device overrides if you want (optional)
    if override_policy:
        for k, v in override_policy.items():
            features[k] = v

    return features


@api_view(["POST"])
def license_heartbeat(request):
    """
    Device calls every 4 hours to obtain a short-lived token.

    Request JSON (minimum):
    {
      "device_uid": "...",
      "serial_number": "...",
      "mac_address": "...",
      "firmware_version": "..."
    }
    """
    device_uid = request.data.get("device_uid")
    serial = request.data.get("serial_number")
    mac = request.data.get("mac_address")
    fw = request.data.get("firmware_version")

    if not device_uid or not serial or not mac:
        return Response({"error": "device_uid, serial_number, mac_address required"}, status=400)

    try:
        device = Device.objects.get(device_uid=device_uid, serial_number=serial, mac_address=mac)
    except Device.DoesNotExist:
        return Response({"status": "denied", "reason": "Unknown device"}, status=404)

    # update last_seen
    device.last_seen_at = timezone.now()
    if fw:
        device.firmware_version = fw
    device.save(update_fields=["last_seen_at", "firmware_version"] if fw else ["last_seen_at"])

    # Find an active device license
    dl = (
        DeviceLicense.objects
        .select_related("subscription", "subscription__bundle")
        .filter(device=device, status=DeviceLicense.Status.ACTIVE)
        .order_by("-activated_at")
        .first()
    )

    if not dl:
        return Response({"status": "denied", "reason": "No active subscription assigned"}, status=403)

    sub = dl.subscription
    computed = sub.computed_status()

    if computed in [sub.Status.EXPIRED, sub.Status.CANCELLED]:
        return Response(
            {
                "status": "denied",
                "reason": computed,
                "end_at": sub.end_at.isoformat(),
                "grace_end_at": sub.grace_end_at().isoformat(),
            },
            status=403,
        )

    bundle = sub.bundle
    features = _build_features(bundle, override_policy=dl.override_policy)

    now = timezone.now()
    exp = now + timedelta(seconds=TOKEN_TTL_SECONDS)
    jti = str(uuid.uuid4())

    payload = {
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "device_uid": device.device_uid,
        "customer_id": str(device.customer_id),
        "subscription_id": str(sub.id),
        "bundle_id": str(bundle.id),
        "sub_status": computed,  # active / in_grace / past_due
        "end_at": sub.end_at.isoformat(),
        "grace_end_at": sub.grace_end_at().isoformat(),
        "features": {
            "mqtt": bool(features.get("mqtt")),
            "sms": bool(features.get("sms")),
            "whatsapp": bool(features.get("whatsapp")),
            "teams": bool(features.get("teams")),
            "telegram": bool(features.get("telegram")),
        },
    }

    # DEV signing: HS256 using Django SECRET_KEY
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")

    return Response(
        {
            "status": "approved",
            "expires_in": TOKEN_TTL_SECONDS,
            "grace": (computed == sub.Status.IN_GRACE),
            "channels": payload["features"],
            "token": token,
        }
    )

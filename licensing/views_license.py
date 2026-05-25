from django.db import transaction
from django.utils import timezone
from rest_framework.decorators import api_view
from rest_framework.response import Response

from .models import Device, DeviceLicense, ValidationLog, GrantToken, Subscription
from .security import (
    build_signing_message,
    sign_message,
    constant_time_compare,
    timestamp_is_fresh,
)
from .tokens import issue_grant_token


@api_view(["POST"])
def validate_license(request):
    device_uid = (request.data.get("device_uid") or "").strip()
    serial_number = (request.data.get("serial_number") or "").strip()
    mac_address = (request.data.get("mac_address") or "").strip()
    nonce = (request.data.get("nonce") or "").strip()
    timestamp = (request.data.get("timestamp") or "").strip()
    signature = (request.data.get("signature") or "").strip()

    ip = request.META.get("REMOTE_ADDR")
    now = timezone.now()

    if not device_uid and not serial_number:
        return Response(
            {"ok": False, "error": "device_uid_or_serial_number_required"},
            status=400,
        )

    if not nonce or not timestamp or not signature:
        return Response(
            {"ok": False, "error": "nonce_timestamp_signature_required"},
            status=400,
        )

    device = None
    if device_uid:
        device = Device.objects.filter(device_uid=device_uid).first()

    if device is None and serial_number:
        device = Device.objects.filter(serial_number=serial_number).first()

    if not device:
        return Response(
            {"ok": False, "valid": False, "error": "device_not_found"},
            status=404,
        )

    if not timestamp_is_fresh(timestamp, max_age_seconds=300):
        ValidationLog.objects.create(
            device=device,
            ip=ip,
            status="DENIED",
            reason="stale_timestamp",
            mac_address=mac_address,
            nonce=nonce,
        )
        return Response(
            {"ok": False, "valid": False, "error": "stale_timestamp"},
            status=403,
        )

    secret = device.device_secret_ciphertext or ""
    if not secret:
        ValidationLog.objects.create(
            device=device,
            ip=ip,
            status="DENIED",
            reason="missing_device_secret",
            mac_address=mac_address,
            nonce=nonce,
        )
        return Response(
            {"ok": False, "valid": False, "error": "missing_device_secret"},
            status=403,
        )

    signing_message = build_signing_message(
        device_uid=device_uid,
        serial_number=serial_number,
        mac_address=mac_address,
        nonce=nonce,
        timestamp=timestamp,
    )
    expected_signature = sign_message(secret, signing_message)

    if not constant_time_compare(signature, expected_signature):
        ValidationLog.objects.create(
            device=device,
            ip=ip,
            status="DENIED",
            reason="invalid_signature",
            mac_address=mac_address,
            nonce=nonce,
        )
        return Response(
            {"ok": False, "valid": False, "error": "invalid_signature"},
            status=403,
        )

    replayed = ValidationLog.objects.filter(
        device=device,
        nonce=nonce,
    ).exists()

    if replayed:
        return Response(
            {"ok": False, "valid": False, "error": "replayed_nonce"},
status=403,
        )

    if device.is_locked_now():
        ValidationLog.objects.create(
            device=device,
            ip=ip,
            status="DENIED",
            reason="device_locked",
            mac_address=mac_address,
            nonce=nonce,
        )
        return Response(
            {"ok": False, "valid": False, "error": "device_locked"},
            status=403,
        )

    if mac_address and device.mac_address and mac_address.lower() != device.mac_address.lower():
        ValidationLog.objects.create(
            device=device,
            ip=ip,
            status="DENIED",
            reason="mac_address_mismatch",
            mac_address=mac_address,
            nonce=nonce,
        )
        return Response(
            {"ok": False, "valid": False, "error": "mac_address_mismatch"},
            status=403,
        )

    device_license = (
        DeviceLicense.objects
        .select_related("subscription__bundle")
        .filter(device=device, status=DeviceLicense.Status.ACTIVE)
        .order_by("-activated_at")
        .first()
    )

    if not device_license:
        ValidationLog.objects.create(
            device=device,
            ip=ip,
            status="DENIED",
            reason="no_active_device_license",
            mac_address=mac_address,
            nonce=nonce,
        )
        return Response(
            {"ok": False, "valid": False, "error": "no_active_device_license"},
            status=403,
        )

    subscription = device_license.subscription
    computed_status = subscription.computed_status()

    if computed_status not in {Subscription.Status.ACTIVE, Subscription.Status.IN_GRACE}:
        ValidationLog.objects.create(
            device=device,
            ip=ip,
            status="DENIED",
            reason=f"subscription_{computed_status}",
            mac_address=mac_address,
            nonce=nonce,
        )
        return Response(
            {
                "ok": False,
                "valid": False,
                "error": f"subscription_{computed_status}",
                "subscription_status": computed_status,
                "expires_at": subscription.end_at.isoformat() if subscription.end_at else None,
            },
            status=403,
        )

    with transaction.atomic():
        device.last_seen_at = now
        device.last_ip = ip
        if mac_address:
            device.mac_address = mac_address
        device.save(update_fields=["last_seen_at", "last_ip", "mac_address"])

        ValidationLog.objects.create(
            device=device,
            ip=ip,
            status="APPROVED",
            reason=f"subscription_{computed_status}",
            mac_address=mac_address,
            nonce=nonce,
        )

        grant = issue_grant_token(
            device=device,
            subscription=subscription,
            bundle_snapshot=subscription.bundle.feature_snapshot(),
        )

        token = GrantToken.objects.create(
            device=device,
            token_jti=grant["jti"],
            issued_at=grant["issued_at"],
            expires_at=grant["expires_at"],
            subscription_status=computed_status,
            bundle_snapshot=subscription.bundle.feature_snapshot(),
        )

    return Response(
        {
            "ok": True,
            "valid": True,
            "device_uid": device.device_uid,
            "subscription_status": computed_status,
            "expires_at": subscription.end_at.isoformat() if subscription.end_at else None,
            "grace_end_at": subscription.grace_end_at().isoformat() if subscription.end_at else None,
            "bundle": subscription.bundle.name,
            "features": subscription.bundle.feature_snapshot(),
            "token_jti": token.token_jti,
            "grant_token": grant["token"],
            "grant_expires_at": grant["expires_at"].isoformat(),
        },
        status=200,
    )

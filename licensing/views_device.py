from django.db import transaction
from django.utils import timezone
from datetime import timedelta

from rest_framework.views import APIView
from rest_framework.response import Response

from django.conf import settings
from django.core.cache import cache
from licensing.security import build_signing_message, sign_message

import time
import hmac
import hashlib
import uuid
import jwt

from .models import (
    Customer,
    Device,
    DeviceModel,
    Subscription,
    DeviceLicense,
    GrantToken,
    ValidationLog,
)
from .serializers_device import DeviceRegisterSerializer

def get_client_ip(request):
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        return xff.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def clone_detect_and_lock(device, ip, mac, nonce):
    window_sec = getattr(settings, "LICENSE_CLONE_WINDOW_SECONDS", 3600)
    max_ips = getattr(settings, "LICENSE_CLONE_MAX_IPS_IN_WINDOW", 2)
    lock_minutes = getattr(settings, "LICENSE_AUTO_LOCKOUT_MINUTES", 120)

    now = timezone.now()
    since = now - timedelta(seconds=window_sec)

    stored_mac = (device.mac_address or "").lower()
    incoming_mac = (mac or "").lower()

    mac_mismatch = stored_mac != incoming_mac

    ip_count = (
        ValidationLog.objects
        .filter(device=device, timestamp__gte=since)
        .exclude(ip__isnull=True)
        .values("ip")
        .distinct()
        .count()
    )

    mac_count = (
        ValidationLog.objects
        .filter(device=device, timestamp__gte=since)
        .exclude(mac_address="")
        .values("mac_address")
        .distinct()
        .count()
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

        if mac_mismatch or device.clone_score >= 3:
            device.lock_status = device.LockStatus.LOCKED
            device.lock_reason = "auto_lockout:" + ",".join(reasons)
            device.lock_until = now + timedelta(minutes=lock_minutes)
            locked = True

        device.save(update_fields=["clone_score", "lock_status", "lock_reason", "lock_until"])

    return {
        "suspected": suspected,
        "locked": locked,
        "reason": ",".join(reasons),
    }


class DeviceRegisterView(APIView):
    authentication_classes = []
    permission_classes = []

    @transaction.atomic
    def post(self, request):
        s = DeviceRegisterSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        d = s.validated_data

        customer_id = d["customer_id"]
        serial = d["serial_number"].strip().upper()
        mac = d["mac_address"].strip().upper()
        device_model_id = d["device_model_id"]

        try:
            customer = Customer.objects.get(pk=customer_id)
        except Customer.DoesNotExist:
            return Response({"error": "customer_not_found"}, status=404)

        try:
            device_model = DeviceModel.objects.get(pk=device_model_id)
        except DeviceModel.DoesNotExist:
            return Response({"error": "device_model_not_found"}, status=404)

        device = Device.objects.filter(
            serial_number=serial,
            mac_address=mac,
        ).first()

        if device:
            device.customer = customer
            device.device_model = device_model
            device.last_seen_at = timezone.now()

            secret = ""
            if not device.device_secret_ciphertext:
                secret = Device.generate_secret()
                device.device_secret_hash = Device.hash_secret(secret)
                device.device_secret_ciphertext = secret

            device.save()

            return Response(
                {
                    "status": "registered",
                    "serial_number": device.serial_number,
                    "mac_address": device.mac_address,
                    "device_uid": device.device_uid,
                    "device_model": str(device.device_model),
                    "device_secret": secret,
                    "licensed": False,
                },
                status=201,
            )

        secret = Device.generate_secret()

        device = Device.objects.create(
            customer=customer,
            serial_number=serial,
            mac_address=mac,
            device_model=device_model,
            device_secret_hash=Device.hash_secret(secret),
            device_secret_ciphertext=secret,
            last_seen_at=timezone.now(),
        )

        return Response(
            {
                "status": "registered",
                "serial_number": device.serial_number,
                "mac_address": device.mac_address,
                "device_uid": device.device_uid,
                "device_model": str(device.device_model),
                "device_secret": secret,
                "licensed": False,
            },
            status=201,
        )
class DeviceValidateView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        serial = request.data.get("serial_number")
        mac = request.data.get("mac_address")
        ts = request.data.get("timestamp")
        nonce = request.data.get("nonce")
        signature = request.data.get("signature")

        ip = get_client_ip(request)

        if not serial or not mac or not ts or not nonce or not signature:
            return Response({"status": "denied", "reason": "missing_fields"}, status=400)

        serial = serial.strip().upper()
        mac = mac.strip().upper()

        device = Device.objects.filter(serial_number=serial).first()
        if not device:
            return Response({"status": "denied", "reason": "unknown_device"}, status=404)

        if device.is_locked_now():
            ValidationLog.objects.create(
                device=device,
                ip=ip,
                status="DENIED",
                reason="device_locked",
                mac_address=mac,
                nonce=nonce,
            )
            return Response({"status": "denied", "reason": "device_locked"}, status=403)

        now = int(time.time())

        if abs(now - int(ts)) > settings.LICENSE_ALLOWED_SKEW_SECONDS:
            ValidationLog.objects.create(
                device=device,
                ip=ip,
                status="DENIED",
                reason="timestamp_skew",
                mac_address=mac,
                nonce=nonce,
            )
            return Response({"status": "denied", "reason": "timestamp_skew"}, status=401)

        key = f"nonce:{serial}:{nonce}"
        if not cache.add(key, "1", timeout=settings.LICENSE_NONCE_TTL_SECONDS):
            ValidationLog.objects.create(
                device=device,
                ip=ip,
                status="DENIED",
                reason="replay_detected",
                mac_address=mac,
                nonce=nonce,
            )
            return Response({"status": "denied", "reason": "replay_detected"}, status=401)

        device_uid = request.data.get("device_uid")

        if not device_uid:
            return Response({"status": "denied", "reason": "missing_device_uid"}, status=400)

        if device_uid != device.device_uid:
            ValidationLog.objects.create(
                device=device,
                ip=ip,
                status="DENIED",
                reason="device_uid_mismatch",
                mac_address=mac,
                nonce=nonce,
            )
            return Response({"status": "denied", "reason": "device_uid_mismatch"}, status=401)

        secret = device.device_secret_ciphertext
        message = build_signing_message(device_uid, serial, mac, nonce, ts)
        expected = sign_message(secret, message)

        if not hmac.compare_digest(expected, signature):
            ValidationLog.objects.create(
                device=device,
                ip=ip,
                status="DENIED",
                reason="unauthorized_signature",
                mac_address=mac,
                nonce=nonce,
            )
            return Response({"status": "denied", "reason": "unauthorized_signature"}, status=401)

        clone_result = clone_detect_and_lock(device, ip, mac, nonce)

        if clone_result["locked"]:
            ValidationLog.objects.create(
                device=device,
                ip=ip,
                status="DENIED",
                reason="clone_lockout",
                mac_address=mac,
                nonce=nonce,
            )
            return Response({"status": "denied", "reason": "clone_lockout"}, status=403)

        dl = (
            DeviceLicense.objects
            .select_related("subscription", "subscription__bundle")
            .filter(device=device, status=DeviceLicense.Status.ACTIVE)
            
            .order_by("-activated_at")
            .first()
        )

        if not dl:
            ValidationLog.objects.create(
                device=device,
                ip=ip,
                status="DENIED",
                reason="no_subscription",
                mac_address=mac,
                nonce=nonce,
            )
            return Response({"status": "denied", "reason": "no_subscription"}, status=403)

        sub = dl.subscription
        computed = sub.computed_status()

        if computed in [sub.Status.EXPIRED, sub.Status.CANCELLED]:
            ValidationLog.objects.create(
                device=device,
                ip=ip,
                status="DENIED",
                reason=computed,
                mac_address=mac,
                nonce=nonce,
            )
            return Response({"status": "denied", "reason": computed}, status=403)

        bundle = sub.bundle
        channels = {
            "mqtt": bundle.allow_mqtt,
            "sms": bundle.allow_sms,
            "whatsapp": bundle.allow_whatsapp,
            "teams": bundle.allow_teams,
            "telegram": bundle.allow_telegram,
        }

        jti = str(uuid.uuid4())
        issued_at = timezone.now()
        expires_at = issued_at + timedelta(seconds=settings.JWT_TTL_SECONDS)

        payload = {
            "jti": jti,
            "iat": int(issued_at.timestamp()),
            "exp": int(expires_at.timestamp()),
            "serial_number": serial,
            "device_uid": device.device_uid,
            "customer_id": str(device.customer_id),
            "subscription_id": str(sub.id),
            "bundle_id": str(bundle.id),
            "channels": channels,
        }

        token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALG)

        GrantToken.objects.get_or_create(
            token_jti=jti,
            defaults={
                "device": device,
                "issued_at": issued_at,
                "expires_at": expires_at,
                "subscription_status": computed,
                "bundle_snapshot": channels,
                "revoked": False,
            },
        )

        device.last_ip = ip
        device.last_seen_at = timezone.now()
        device.save(update_fields=["last_ip", "last_seen_at"])

        ValidationLog.objects.create(
            device=device,
            ip=ip,
            status="APPROVED",
            reason="approved",
            mac_address=mac,
            nonce=nonce,
        )

        return Response(
            {
                "status": "approved",
                "token": token,
                "expires_in": settings.JWT_TTL_SECONDS,
                "channels": channels,
                "clone_suspected": clone_result["suspected"],
            }
        )
        
        
class DeviceActivateView(APIView):
    authentication_classes = []
    permission_classes = []

    @transaction.atomic
    def post(self, request):
        device_uid = request.data.get("device_uid")
        payment_reference = request.data.get("payment_reference")

        if not device_uid or not payment_reference:
            return Response(
                {"error": "device_uid and payment_reference are required"},
                status=400,
            )

        try:
            device = Device.objects.get(device_uid=device_uid)
        except Device.DoesNotExist:
            return Response({"error": "device_not_found"}, status=404)

        subscription = (
            Subscription.objects
            .select_related("bundle", "customer")
            .filter(payment_reference=payment_reference)
            .first()
        )

        if not subscription:
            return Response({"error": "subscription_not_found"}, status=404)

        computed_status = subscription.computed_status()
        if computed_status not in {
            Subscription.Status.ACTIVE,
            Subscription.Status.IN_GRACE,
        }:
            return Response(
                {
                    "error": "subscription_not_usable",
                    "subscription_status": computed_status,
                },
                status=403,
            )

        if device.customer_id != subscription.customer_id:
            return Response({"error": "device_customer_mismatch"}, status=403)

        devices_cap = subscription.bundle.devices_cap
        if devices_cap is not None:
            active_count = DeviceLicense.objects.filter(
                subscription=subscription,
                status=DeviceLicense.Status.ACTIVE,
            ).count()

            already_linked = DeviceLicense.objects.filter(
                subscription=subscription,
                device=device,
            ).exists()

            if not already_linked and active_count >= devices_cap:
                return Response(
                    {"error": "device_cap_reached", "devices_cap": devices_cap},
                    status=403,
                )

        device_license, created = DeviceLicense.objects.get_or_create(
            device=device,
            subscription=subscription,
            defaults={"status": DeviceLicense.Status.ACTIVE},
        )

        if not created and device_license.status != DeviceLicense.Status.ACTIVE:
            device_license.status = DeviceLicense.Status.ACTIVE
            device_license.revoked_at = None
            device_license.save(update_fields=["status", "revoked_at"])

        return Response(
            {
                "ok": True,
                "device_uid": device.device_uid,
                "subscription_id": str(subscription.id),
                "subscription_status": computed_status,
                "bundle": subscription.bundle.name,
                "features": subscription.bundle.feature_snapshot(),
                "expires_at": subscription.end_at.isoformat(),
                "activated": True,
            },
            status=200,
        )

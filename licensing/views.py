from django.db import transaction
from django.utils import timezone
from rest_framework.decorators import api_view
from rest_framework.response import Response

from .models import Customer, Device, Subscription, DeviceLicense


@api_view(["POST"])
def register_device(request):
    customer_id = request.data.get("customer_id")
    device_uid = request.data.get("device_uid")
    serial_number = request.data.get("serial_number")
    mac_address = request.data.get("mac_address")
    model = request.data.get("model")
    firmware_version = request.data.get("firmware_version")

    if not customer_id or not device_uid or not serial_number or not mac_address:
        return Response(
            {
                "error": "customer_id, device_uid, serial_number and mac_address are required"
            },
            status=400,
        )

    try:
        customer = Customer.objects.get(id=customer_id)
    except Customer.DoesNotExist:
        return Response({"error": "customer_not_found"}, status=404)

    device, created = Device.objects.get_or_create(
        serial_number=serial_number,
        defaults={
            "customer": customer,
            "device_uid": device_uid,
            "mac_address": mac_address,
            "model": model,
            "firmware_version": firmware_version,
            "last_seen_at": timezone.now(),
        },
    )

    raw_secret = None

    if created:
        raw_secret = Device.generate_secret()
        device.device_secret_hash = Device.hash_secret(raw_secret)
        device.device_secret_ciphertext = raw_secret  # dev only; encrypt in production
        device.save(update_fields=["device_secret_hash", "device_secret_ciphertext"])
    else:
        device.customer = customer
        device.device_uid = device_uid
        device.mac_address = mac_address
        device.model = model or device.model
        device.firmware_version = firmware_version or device.firmware_version
        device.last_seen_at = timezone.now()

        if not device.device_secret_ciphertext:
            raw_secret = Device.generate_secret()
            device.device_secret_hash = Device.hash_secret(raw_secret)
            device.device_secret_ciphertext = raw_secret

        device.save(
            update_fields=[
                "customer",
                "device_uid",
                "mac_address",
                "model",
                "firmware_version",
                "last_seen_at",
                "device_secret_hash",
                "device_secret_ciphertext",
            ]
        )

    response = {
        "ok": True,
        "device_id": str(device.id),
        "device_uid": device.device_uid,
        "serial_number": device.serial_number,
        "created": created,
    }

    # Return once so the installer/device can store it securely
    if raw_secret:
        response["device_secret"] = raw_secret

    return Response(response, status=201 if created else 200)



# licensing/models.py
import hashlib
import secrets
import uuid
from datetime import timedelta

import pycountry
import pytz
from django.db import models
from django.utils import timezone


def generate_customer_id():
    return uuid.uuid4().hex


def generate_device_uid_from_identity(serial_number: str, mac_address: str) -> str:
    """
    Generate a stable UUID-like device UID from serial number + MAC address.
    Same serial + MAC will always produce the same UID.
    """
    identity = f"{serial_number.strip().upper()}::{mac_address.strip().upper()}"
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, identity))


class Customer(models.Model):
    id = models.CharField(
        primary_key=True,
        max_length=32,
        default=generate_customer_id,
        editable=False,
    )

    company_name = models.CharField(max_length=255)
    billing_email = models.EmailField(blank=True, null=True)
    tech_email = models.EmailField(blank=True, null=True)

    country_name = models.CharField(max_length=100, blank=True)
    country_code = models.CharField(max_length=5, blank=True)
    timezone = models.CharField(max_length=50, default="UTC")

    def save(self, *args, **kwargs):
        self.country_code = ""
        self.timezone = "UTC"

        if self.country_name:
            try:
                country = pycountry.countries.lookup(self.country_name)
                self.country_name = country.name
                self.country_code = country.alpha_2

                country_timezones = pytz.country_timezones.get(self.country_code)
                if country_timezones:
                    self.timezone = country_timezones[0]
            except LookupError:
                pass

        super().save(*args, **kwargs)

    def __str__(self):
        return self.company_name

    @property
    def country_display(self):
        if self.country_name and self.country_code:
            return f"{self.country_name} ({self.country_code})"
        return self.country_name or ""


class Manufacturer(models.Model):
    name = models.CharField(max_length=100)

    def __str__(self):
        return self.name


class DeviceModel(models.Model):
    manufacturer = models.ForeignKey(
        Manufacturer,
        on_delete=models.CASCADE,
        related_name="device_models",
    )
    name = models.CharField(max_length=100)

    def __str__(self):
        return f"{self.manufacturer} - {self.name}"


class Bundle(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=150, unique=True)

    allow_mqtt = models.BooleanField(default=False)
    allow_sms = models.BooleanField(default=False)
    allow_whatsapp = models.BooleanField(default=False)
    allow_teams = models.BooleanField(default=False)
    allow_telegram = models.BooleanField(default=False)

    daily_message_cap = models.IntegerField(blank=True, null=True)
    devices_cap = models.IntegerField(blank=True, null=True)

    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def feature_snapshot(self) -> dict:
        return {
            "mqtt": self.allow_mqtt,
            "sms": self.allow_sms,
            "whatsapp": self.allow_whatsapp,
            "teams": self.allow_teams,
            "telegram": self.allow_telegram,
            "daily_message_cap": self.daily_message_cap,
            "devices_cap": self.devices_cap,
        }

    def __str__(self):
        return self.name


class BundlePrice(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    bundle = models.ForeignKey(Bundle, on_delete=models.CASCADE, related_name="prices")

    currency = models.CharField(max_length=10, default="ZAR")
    annual_price = models.DecimalField(max_digits=12, decimal_places=2)

    effective_from = models.DateField()
    effective_to = models.DateField(blank=True, null=True)
    region = models.CharField(max_length=100, blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["bundle", "effective_from"]),
        ]

    def __str__(self):
        return f"{self.bundle.name} - {self.currency} {self.annual_price}"


class Subscription(models.Model):
    class Status(models.TextChoices):
        ACTIVE = "active"
        PAST_DUE = "past_due"
        IN_GRACE = "in_grace"
        EXPIRED = "expired"
        CANCELLED = "cancelled"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE, related_name="subscriptions")
    bundle = models.ForeignKey(Bundle, on_delete=models.PROTECT, related_name="subscriptions")

    status = models.CharField(max_length=30, choices=Status.choices, default=Status.ACTIVE)

    start_at = models.DateTimeField()
    end_at = models.DateTimeField()
    grace_days = models.IntegerField(default=15)
    auto_renew = models.BooleanField(default=False)

    payment_provider = models.CharField(max_length=50, blank=True, null=True)
    provider_customer_id = models.CharField(max_length=255, blank=True, null=True)
    provider_subscription_id = models.CharField(max_length=255, blank=True, null=True)
    payment_reference = models.CharField(max_length=255, blank=True, null=True, db_index=True)

    last_payment_at = models.DateTimeField(blank=True, null=True)
    next_billing_at = models.DateTimeField(blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def grace_end_at(self):
        return self.end_at + timedelta(days=self.grace_days)

    def computed_status(self) -> str:
        now = timezone.now()
        if self.status == self.Status.CANCELLED:
            return self.Status.CANCELLED
        if now <= self.end_at:
            return self.Status.ACTIVE
        if self.end_at < now <= self.grace_end_at():
            return self.Status.IN_GRACE
        return self.Status.EXPIRED

    def __str__(self):
        return f"{self.customer.company_name} - {self.bundle.name}"


class Device(models.Model):
    """
    Gateway device (Teltonika TRB/RUT etc).
    """
    class LockStatus(models.TextChoices):
        OK = "ok"
        CLONE_SUSPECTED = "clone_suspected"
        LOCKED = "locked"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE, related_name="devices")

    device_uid = models.CharField(max_length=36, unique=True, blank=True)
    serial_number = models.CharField(max_length=255, unique=True)
    mac_address = models.CharField(max_length=50)

    device_model = models.ForeignKey(
        DeviceModel,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="devices",
    )

    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(blank=True, null=True)

    device_secret_hash = models.CharField(max_length=64, blank=True, default="")
    device_secret_ciphertext = models.TextField(
    blank=True, default="")
    last_ip = models.GenericIPAddressField(null=True, blank=True)

    lock_status = models.CharField(
        max_length=30,
        choices=LockStatus.choices,
        default=LockStatus.OK,
    )
    lock_reason = models.CharField(max_length=255, blank=True, default="")
    lock_until = models.DateTimeField(null=True, blank=True)
    clone_score = models.PositiveIntegerField(default=0)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["customer", "device_uid"]),
            models.Index(fields=["serial_number"]),
        ]

    def save(self, *args, **kwargs):
        if self.serial_number:
            self.serial_number = self.serial_number.strip().upper()

        if self.mac_address:
            self.mac_address = self.mac_address.strip().upper()

        if not self.device_uid and self.serial_number and self.mac_address:
            self.device_uid = generate_device_uid_from_identity(
                self.serial_number,
                self.mac_address,
            )

        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.device_uid or 'pending-uid'} ({self.device_model or 'unknown'})"

    def is_locked_now(self) -> bool:
        if self.lock_status != self.LockStatus.LOCKED:
            return False
        if not self.lock_until:
            return True
        return timezone.now() < self.lock_until

    @staticmethod
    def generate_secret() -> str:
        return secrets.token_hex(32)

    @staticmethod
    def hash_secret(secret: str) -> str:
        return hashlib.sha256(secret.encode("utf-8")).hexdigest()
        
        
class DeviceLicense(models.Model):
    class Status(models.TextChoices):
        ACTIVE = "active"
        REVOKED = "revoked"
        SUSPENDED = "suspended"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name="licenses")
    subscription = models.ForeignKey(
        Subscription,
        on_delete=models.CASCADE,
        related_name="device_licenses",
    )

    status = models.CharField(max_length=30, choices=Status.choices, default=Status.ACTIVE)
    activated_at = models.DateTimeField(auto_now_add=True)
    revoked_at = models.DateTimeField(blank=True, null=True)

    override_policy = models.JSONField(blank=True, null=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["device", "subscription"],
                name="uniq_device_subscription",
            )
        ]

    def __str__(self):
        return f"{self.device.serial_number} -> {self.subscription}"


class GrantToken(models.Model):
    """
    Optional: store issued token JTIs to support revocation, auditing, token search.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name="grant_tokens")

    token_jti = models.CharField(max_length=255, unique=True)
    issued_at = models.DateTimeField()
    expires_at = models.DateTimeField()

    subscription_status = models.CharField(max_length=30)
    bundle_snapshot = models.JSONField()

    revoked = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["expires_at"]),
            models.Index(fields=["device", "issued_at"]),
        ]

    def __str__(self):
        return self.token_jti


class PaymentTransaction(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    subscription = models.ForeignKey(
        Subscription,
        on_delete=models.CASCADE,
        related_name="transactions",
    )

    provider_txn_id = models.CharField(max_length=255, unique=True)
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    currency = models.CharField(max_length=10, default="ZAR")
    status = models.CharField(max_length=30)
    paid_at = models.DateTimeField(blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.provider_txn_id


class PaymentEvent(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    subscription = models.ForeignKey(
        Subscription,
        on_delete=models.CASCADE,
        related_name="payment_events",
    )

    provider = models.CharField(max_length=50)
    event_id = models.CharField(max_length=255, unique=True)
    event_type = models.CharField(max_length=100)
    payload = models.JSONField()

    received_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.provider} - {self.event_type}"


class SubscriptionReminder(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    subscription = models.ForeignKey(
        Subscription,
        on_delete=models.CASCADE,
        related_name="reminders",
    )

    reminder_type = models.CharField(max_length=30)
    sent_at = models.DateTimeField()
    email_to = models.EmailField()

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["subscription", "reminder_type"],
                name="uniq_sub_reminder_type",
            )
        ]

    def __str__(self):
        return f"{self.subscription} - {self.reminder_type}"


class ValidationLog(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name="validation_logs")

    timestamp = models.DateTimeField(auto_now_add=True)
    ip = models.GenericIPAddressField(null=True, blank=True)

    status = models.CharField(max_length=24)
    reason = models.CharField(max_length=255, blank=True, default="")

    mac_address = models.CharField(max_length=50, blank=True, default="")
    nonce = models.CharField(max_length=64, blank=True, default="")

    class Meta:
        indexes = [
            models.Index(fields=["device", "timestamp"]),
            models.Index(fields=["timestamp"]),
        ]
        constraints = [
            models.UniqueConstraint(fields=["device", "nonce"], name="uniq_device_nonce")
        ]

    def __str__(self):
        return f"{self.timestamp} {self.device.serial_number} {self.status} {self.reason}"

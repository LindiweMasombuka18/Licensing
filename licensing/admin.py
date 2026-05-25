from django.contrib import admin
from django import forms
from .models import Device
import pycountry

from .models import (
    Customer, Bundle, BundlePrice, Subscription,
    Device, DeviceLicense, GrantToken,
    PaymentTransaction, PaymentEvent,
    SubscriptionReminder, ValidationLog,  Manufacturer, DeviceModel
)


COUNTRY_CHOICES = [("", "---------")] + sorted(
    [(country.name, country.name) for country in pycountry.countries],
    key=lambda x: x[1]
)


class CustomerAdminForm(forms.ModelForm):
    country_name = forms.ChoiceField(
        choices=COUNTRY_CHOICES,
        required=False,
        label="Country name"
    )

    class Meta:
        model = Customer
        fields = "__all__"

    def clean(self):
        cleaned_data = super().clean()
        country_name = cleaned_data.get("country_name")

        if country_name:
            try:
                country = pycountry.countries.lookup(country_name)
                cleaned_data["country_code"] = country.alpha_2
            except LookupError:
                cleaned_data["country_code"] = ""
        else:
            cleaned_data["country_code"] = ""

        return cleaned_data


@admin.register(Customer)
class CustomerAdmin(admin.ModelAdmin):
    form = CustomerAdminForm

    list_display = (
        "company_name",
        "billing_email",
        "tech_email",
        "country_display",
        "timezone",
    )

    search_fields = (
        "company_name",
        "billing_email",
        "tech_email",
        "country_name",
        "country_code",
    )

    fields = (
        "company_name",
        "billing_email",
        "tech_email",
        ("country_name", "country_code"),
        "timezone",
    )

    readonly_fields = ("country_code", "timezone")

    class Media:
        js = ("licensing/country_auto_fill.js",)


admin.site.register(Bundle)
admin.site.register(BundlePrice)
admin.site.register(Subscription)
admin.site.register(DeviceLicense)
admin.site.register(PaymentTransaction)
admin.site.register(PaymentEvent)
admin.site.register(SubscriptionReminder)
admin.site.register(ValidationLog)

@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = (
        "device_uid",
        "serial_number",
        "mac_address",
        "device_model",
        "customer",
        "lock_status",
        "clone_score",
        "last_seen_at",
    )

    list_display_links = ("device_uid",)

    search_fields = (
        "device_uid",
        "serial_number",
        "mac_address",
        "customer__company_name",
        "device_model__name",
        "device_model__manufacturer__name",
    )

    autocomplete_fields = ("customer", "device_model")

    readonly_fields = (
        "lock_reason",
    )

    exclude = (
        "device_uid",
        "device_secret_hash",
        "device_secret_ciphertext",
    )

@admin.register(GrantToken)
class GrantTokenAdmin(admin.ModelAdmin):
    list_display = (
        "issued_at",
        "device",
        "token_jti",
        "expires_at",
        "subscription_status",
        "revoked"
    )

    list_filter = (
        "revoked",
        "subscription_status"
    )

    search_fields = (
        "token_jti",
        "device__serial_number",
        "device__device_uid",
        "device__mac_address"
    )
    
@admin.register(Manufacturer)
class ManufacturerAdmin(admin.ModelAdmin):
    search_fields = ("name",)
    list_display = ("name",)
    
@admin.register(DeviceModel)
class DeviceModelAdmin(admin.ModelAdmin):
    list_display = ("name", "manufacturer")
    list_filter = ("manufacturer",)
    search_fields = ("name", "manufacturer__name")
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    

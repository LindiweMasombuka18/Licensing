from django.urls import path

from .views import register_device, activate_device
from .views_license import validate_license
from .views_payments import payfast_itn

urlpatterns = [
    path("api/register/", register_device, name="register_device"),
    path("api/activate/", activate_device, name="activate_device"),
    path("api/validate/", validate_license, name="validate_license"),
    path("payments/payfast/itn/", payfast_itn, name="payfast_itn"),
]

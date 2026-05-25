from django.urls import path, include

from .views_device import DeviceRegisterView, DeviceActivateView, DeviceValidateView
from .views_tokens import verify_token

urlpatterns = [
    path("payments/", include("licensing.urls_payments")),

    path("register/", DeviceRegisterView.as_view(), name="register_device"),
    path("activate/", DeviceActivateView.as_view(), name="activate_device"),
    path("validate/", DeviceValidateView.as_view(), name="validate_device"),
    path("token/verify/", verify_token, name="verify_token"),
]

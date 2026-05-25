from django.urls import path
from .views_device import DeviceRegisterView, DeviceValidateView

urlpatterns = [
    path("device/register/", DeviceRegisterView.as_view()),
    path("device/validate/", DeviceValidateView.as_view()),
]

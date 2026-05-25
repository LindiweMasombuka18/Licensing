from django.urls import path
from .views_payments import payfast_itn

urlpatterns = [
    path("payfast/itn/", payfast_itn, name="payfast_itn"),
]

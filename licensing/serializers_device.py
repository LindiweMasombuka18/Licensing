from rest_framework import serializers


class DeviceRegisterSerializer(serializers.Serializer):
    customer_id = serializers.CharField()
    serial_number = serializers.CharField(max_length=255)
    mac_address = serializers.CharField(max_length=50)
    device_model_id = serializers.IntegerField()

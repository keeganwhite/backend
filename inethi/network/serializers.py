from rest_framework import serializers
from .models import Host, Ping, Network
from user.serializers import UserSerializer


class HostSerializer(serializers.ModelSerializer):
    # include the user's details when reading a device.
    user_detail = UserSerializer(source="user", read_only=True)

    class Meta:
        model = Host

        fields = [
            "id",
            "name",
            "ip_address",
            "mac_address",
            "device_type",
            "user",  # for writing
            "user_detail",  # for reading and displaying user info
            "radiusdesk_instance",
            "cloud",
            "realm",
            "network"
        ]


class PingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Ping
        fields = '__all__'


class NetworkSerializer(serializers.ModelSerializer):
    class Meta:
        model = Network
        fields = ['id', 'name', 'created_by', 'created_at']
        read_only_fields = ['created_by', 'created_at']

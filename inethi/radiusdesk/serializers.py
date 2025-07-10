from rest_framework import serializers
from .models import (
    RadiusDeskInstance,
    Cloud,
    Realm,
    RadiusDeskProfile,
    Voucher
)


class RadiusDeskInstanceSerializer(serializers.ModelSerializer):
    class Meta:
        model = RadiusDeskInstance
        fields = '__all__'


class CloudSerializer(serializers.ModelSerializer):
    class Meta:
        model = Cloud
        fields = '__all__'


class RealmSerializer(serializers.ModelSerializer):
    class Meta:
        model = Realm
        fields = '__all__'


class RadiusDeskProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = RadiusDeskProfile
        fields = '__all__'


class VoucherSerializer(serializers.ModelSerializer):
    radius_desk_instance_name = serializers.CharField(
        source="radius_desk_instance.name", read_only=True
    )

    class Meta:
        model = Voucher
        fields = '__all__'

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
        fields = [
            'id',
            'name', 
            'base_url',
            'administrators',
            'accepts_crypto'
        ]
        # Explicitly exclude sensitive fields: username, password, token


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
    profile_name = serializers.SerializerMethodField()
    profile_data_limit_gb = serializers.SerializerMethodField()
    profile_data_limit_enabled = serializers.SerializerMethodField()
    profile_speed_limit_mbs = serializers.SerializerMethodField()
    profile_speed_limit_enabled = serializers.SerializerMethodField()
    profile_cost = serializers.SerializerMethodField()

    def get_profile_name(self, obj):
        """Get the profile name for this voucher."""
        return obj.profile.name if obj.profile else None

    def get_profile_data_limit_gb(self, obj):
        """Get the profile data limit in GB."""
        return obj.profile.data_limit_gb if obj.profile else None

    def get_profile_data_limit_enabled(self, obj):
        """Get whether data limit is enabled for the profile."""
        return obj.profile.data_limit_enabled if obj.profile else False

    def get_profile_speed_limit_mbs(self, obj):
        """Get the profile speed limit in MB/s."""
        return obj.profile.speed_limit_mbs if obj.profile else None

    def get_profile_speed_limit_enabled(self, obj):
        """Get whether speed limit is enabled for the profile."""
        return obj.profile.speed_limit_enabled if obj.profile else False

    def get_profile_cost(self, obj):
        """Get the profile cost."""
        return obj.profile.cost if obj.profile else None

    class Meta:
        model = Voucher
        fields = '__all__'

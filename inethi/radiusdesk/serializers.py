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
    profile_name = serializers.SerializerMethodField()
    profile_data_limit_gb = serializers.SerializerMethodField()
    profile_data_limit_enabled = serializers.SerializerMethodField()
    profile_speed_limit_mbs = serializers.SerializerMethodField()
    profile_speed_limit_enabled = serializers.SerializerMethodField()
    profile_cost = serializers.SerializerMethodField()

    def get_profile_name(self, obj):
        """Get the profile name for this voucher through its realm."""
        profile = obj.realm.profiles.filter(
            radius_desk_instance=obj.radius_desk_instance
        ).first()
        return profile.name if profile else None

    def get_profile_data_limit_gb(self, obj):
        """Get the profile data limit in GB."""
        profile = obj.realm.profiles.filter(
            radius_desk_instance=obj.radius_desk_instance
        ).first()
        return profile.data_limit_gb if profile else None

    def get_profile_data_limit_enabled(self, obj):
        """Get whether data limit is enabled for the profile."""
        profile = obj.realm.profiles.filter(
            radius_desk_instance=obj.radius_desk_instance
        ).first()
        return profile.data_limit_enabled if profile else False

    def get_profile_speed_limit_mbs(self, obj):
        """Get the profile speed limit in MB/s."""
        profile = obj.realm.profiles.filter(
            radius_desk_instance=obj.radius_desk_instance
        ).first()
        return profile.speed_limit_mbs if profile else None

    def get_profile_speed_limit_enabled(self, obj):
        """Get whether speed limit is enabled for the profile."""
        profile = obj.realm.profiles.filter(
            radius_desk_instance=obj.radius_desk_instance
        ).first()
        return profile.speed_limit_enabled if profile else False

    def get_profile_cost(self, obj):
        """Get the profile cost."""
        profile = obj.realm.profiles.filter(
            radius_desk_instance=obj.radius_desk_instance
        ).first()
        return profile.cost if profile else None

    class Meta:
        model = Voucher
        fields = '__all__'

from rest_framework import serializers
from .models import (
    RadiusDeskInstance,
    Cloud,
    Realm,
    RadiusDeskProfile,
    Voucher,
    RadiusDeskUser
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


class PublicRadiusDeskInstanceSerializer(serializers.ModelSerializer):
    """Public serializer for RadiusDeskInstance with only non-sensitive fields."""
    class Meta:
        model = RadiusDeskInstance
        fields = [
            'id',
            'name',
            'accepts_crypto'
        ]
        read_only_fields = ['id', 'name', 'accepts_crypto']


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


class RadiusDeskUserSerializer(serializers.ModelSerializer):
    """Serializer for RadiusDeskUser model."""
    radius_desk_instance_name = serializers.CharField(
        source="radius_desk_instance.name", read_only=True
    )
    profile_name = serializers.CharField(
        source="profile.name", read_only=True, allow_null=True
    )
    user_email = serializers.CharField(
        source="user.email", read_only=True
    )
    user_username = serializers.CharField(
        source="user.username", read_only=True
    )

    class Meta:
        model = RadiusDeskUser
        fields = [
            'id',
            'user',
            'user_email',
            'user_username',
            'radius_desk_instance',
            'radius_desk_instance_name',
            'username',
            'radiusdesk_id',
            'profile',
            'profile_name',
            'created_at',
            'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'radiusdesk_id']
        # Exclude password from serialization for security


class CreateRadiusDeskUserSerializer(serializers.Serializer):
    """Serializer for creating a permanent user in RadiusDesk."""
    radius_desk_instance_pk = serializers.IntegerField(
        help_text="Primary key of the RadiusDesk instance"
    )
    profile_pk = serializers.IntegerField(
        help_text="Primary key of the RadiusDesk profile to assign"
    )
    username = serializers.CharField(
        max_length=255,
        help_text="Username for the permanent user (optional, auto-generated if not provided)",
        required=False,
        allow_blank=True
    )
    password = serializers.CharField(
        max_length=255,
        help_text="Password for the permanent user"
    )
    name = serializers.CharField(
        max_length=255,
        required=False,
        allow_blank=True,
        help_text="First name"
    )
    surname = serializers.CharField(
        max_length=255,
        required=False,
        allow_blank=True,
        help_text="Last name"
    )
    email = serializers.EmailField(
        required=False,
        allow_blank=True,
        help_text="Email address"
    )
    phone = serializers.CharField(
        max_length=50,
        required=False,
        allow_blank=True,
        help_text="Phone number"
    )


class AddDataTopUpSerializer(serializers.Serializer):
    """Serializer for adding data top-up to a permanent user."""
    amount = serializers.IntegerField(
        min_value=1,
        help_text="Amount of data to add"
    )
    unit = serializers.ChoiceField(
        choices=['mb', 'gb'],
        default='gb',
        help_text="Unit for data amount (mb or gb)"
    )
    comment = serializers.CharField(
        max_length=255,
        required=False,
        allow_blank=True,
        default="",
        help_text="Optional comment for the top-up"
    )

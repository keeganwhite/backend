from rest_framework import serializers
from .models import (
    OCSInstance,
    OCSProductOffering,
    OCSSubscriber,
    DataBundle,
    DataPurchase,
    TopUpHistory
)


class OCSInstanceSerializer(serializers.ModelSerializer):
    class Meta:
        model = OCSInstance
        fields = [
            'id',
            'name',
            'base_url',
            'administrators',
            'accepts_crypto',
            'verify_ssl'
        ]
        # Explicitly exclude sensitive fields: username, password


class PublicOCSInstanceSerializer(serializers.ModelSerializer):
    """Public serializer for OCSInstance with only non-sensitive fields."""
    class Meta:
        model = OCSInstance
        fields = [
            'id',
            'name',
            'accepts_crypto'
        ]
        read_only_fields = ['id', 'name', 'accepts_crypto']


class OCSProductOfferingSerializer(serializers.ModelSerializer):
    ocs_instance_name = serializers.CharField(
        source="ocs_instance.name",
        read_only=True
    )

    class Meta:
        model = OCSProductOffering
        fields = [
            'id',
            'name',
            'ocs_instance',
            'ocs_instance_name',
            'offering_id',
            'description',
            'price',
            'data_mb',
            'validity_days',
            'is_active',
            'created_at',
            'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class OCSSubscriberSerializer(serializers.ModelSerializer):
    """Serializer for OCSSubscriber model."""
    ocs_instance_name = serializers.CharField(
        source="ocs_instance.name", read_only=True
    )
    user_email = serializers.CharField(
        source="user.email", read_only=True
    )
    user_username = serializers.CharField(
        source="user.username", read_only=True
    )

    class Meta:
        model = OCSSubscriber
        fields = [
            'id',
            'user',
            'user_email',
            'user_username',
            'ocs_instance',
            'ocs_instance_name',
            'imsi',
            'phone_number',
            'service_id',
            'product_id',
            'created_at',
            'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'service_id', 'product_id']


class CreateOCSSubscriberSerializer(serializers.Serializer):
    """Serializer for creating an OCS subscriber."""
    ocs_instance_pk = serializers.IntegerField(
        help_text="Primary key of the OCS instance"
    )
    imsi = serializers.CharField(
        max_length=15,
        min_length=15,
        help_text="SIM card IMSI (15 digits)"
    )
    phone_number = serializers.CharField(
        max_length=20,
        help_text="Phone number in international format"
    )
    offering_id = serializers.CharField(
        help_text="Product offering ID to subscribe to"
    )
    initial_balance_bytes = serializers.IntegerField(
        default=1000000000,
        min_value=0,
        help_text="Initial balance in bytes (default: 1GB)"
    )

    def validate_imsi(self, value):
        """Validate IMSI format (15 digits)."""
        if not value.isdigit() or len(value) != 15:
            raise serializers.ValidationError("IMSI must be exactly 15 digits")
        return value

    def validate_phone_number(self, value):
        """Validate phone number format."""
        if not value.startswith('+'):
            raise serializers.ValidationError("Phone number must start with '+' (international format)")
        if len(value) < 10 or len(value) > 20:
            raise serializers.ValidationError("Phone number must be between 10 and 20 characters")
        return value


class DataBundleSerializer(serializers.ModelSerializer):
    """Serializer for DataBundle model."""
    ocs_instance_name = serializers.CharField(
        source="ocs_instance.name",
        read_only=True
    )
    product_offering_name = serializers.CharField(
        source="product_offering.name",
        read_only=True
    )

    class Meta:
        model = DataBundle
        fields = [
            'id',
            'name',
            'ocs_instance',
            'ocs_instance_name',
            'product_offering',
            'product_offering_name',
            'price',
            'payment_method',
            'data_mb',
            'is_active',
            'created_at',
            'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class DataPurchaseSerializer(serializers.ModelSerializer):
    """Serializer for DataPurchase model."""
    user_username = serializers.CharField(
        source="user.username",
        read_only=True
    )
    bundle_name = serializers.CharField(
        source="bundle.name",
        read_only=True
    )
    ocs_subscriber_imsi = serializers.CharField(
        source="ocs_subscriber.imsi",
        read_only=True
    )

    class Meta:
        model = DataPurchase
        fields = [
            'id',
            'user',
            'user_username',
            'bundle',
            'bundle_name',
            'ocs_subscriber',
            'ocs_subscriber_imsi',
            'transaction',
            'payment_method',
            'amount_paid',
            'purchase_date',
            'status'
        ]
        read_only_fields = ['id', 'purchase_date']


class PurchaseDataBundleSerializer(serializers.Serializer):
    """Input serializer for purchasing a data bundle."""
    bundle_id = serializers.IntegerField(
        help_text="ID of the DataBundle to purchase"
    )
    oneforyou_pin = serializers.CharField(
        required=False, 
        allow_blank=True,
        help_text="1FourYou voucher PIN (required for 1foryou payment method)"
    )
    phone_number = serializers.CharField(
        required=False, 
        allow_blank=True,
        help_text="Customer phone number (required for 1foryou payment method)"
    )
    
    def validate(self, data):
        """Validate that 1FourYou fields are provided when needed."""
        bundle_id = data.get('bundle_id')
        oneforyou_pin = data.get('oneforyou_pin')
        phone_number = data.get('phone_number')
        
        if bundle_id:
            try:
                from .models import DataBundle
                bundle = DataBundle.objects.get(pk=bundle_id)
                
                # If payment method is 1foryou, require PIN and phone number
                if bundle.payment_method == '1foryou':
                    if not oneforyou_pin:
                        raise serializers.ValidationError({
                            'oneforyou_pin': '1FourYou PIN is required for 1foryou payment method.'
                        })
                    if not phone_number:
                        raise serializers.ValidationError({
                            'phone_number': 'Phone number is required for 1foryou payment method.'
                        })
                        
            except DataBundle.DoesNotExist:
                pass  # Will be caught by other validation
        
        return data


class OnboardRequestSerializer(serializers.Serializer):
    """Serializer for simplified onboarding request."""
    imsi = serializers.CharField(max_length=16, min_length=14)
    multiSession = serializers.BooleanField(required=False, default=False)
    ocs_instance_id = serializers.IntegerField(required=True)

    def validate_imsi(self, value: str) -> str:
        if not value.isdigit():
            raise serializers.ValidationError("IMSI must contain only digits")
        return value


class TopupRequestSerializer(serializers.Serializer):
    """Top-up by selecting a data bundle; resolve instance/amount from bundle."""
    bundle_id = serializers.IntegerField()
    imsi = serializers.CharField(required=False, allow_blank=True)
    description = serializers.CharField(required=False, allow_blank=True, max_length=255)
    oneforyou_pin = serializers.CharField(required=False, allow_blank=True, help_text="1FourYou voucher PIN (required for 1foryou payment method)")
    phone_number = serializers.CharField(required=False, allow_blank=True, help_text="Customer phone number (required for 1foryou payment method)")

    def validate_bundle_id(self, value):
        if value <= 0:
            raise serializers.ValidationError("bundle_id must be a positive integer")
        return value
    
    def validate(self, data):
        """Validate that 1FourYou fields are provided when needed."""
        bundle_id = data.get('bundle_id')
        oneforyou_pin = data.get('oneforyou_pin')
        phone_number = data.get('phone_number')
        
        if bundle_id:
            try:
                from .models import DataBundle
                bundle = DataBundle.objects.get(pk=bundle_id)
                
                # If payment method is 1foryou, require PIN and phone number
                if bundle.payment_method == '1foryou':
                    if not oneforyou_pin:
                        raise serializers.ValidationError({
                            'oneforyou_pin': '1FourYou PIN is required for 1foryou payment method.'
                        })
                    if not phone_number:
                        raise serializers.ValidationError({
                            'phone_number': 'Phone number is required for 1foryou payment method.'
                        })
                        
            except DataBundle.DoesNotExist:
                pass  # Will be caught by other validation
        
        return data


class TopUpHistorySerializer(serializers.ModelSerializer):
    """Serializer for TopUpHistory model."""
    bundle_name = serializers.CharField(source="bundle.name", read_only=True)
    bundle_data_mb = serializers.IntegerField(source="bundle.data_mb", read_only=True)
    amount_gb = serializers.SerializerMethodField()
    imsi = serializers.CharField(source="mapping.imsi", read_only=True)

    class Meta:
        model = TopUpHistory
        fields = [
            'id',
            'mapping',
            'imsi',
            'bundle',
            'bundle_name',
            'bundle_data_mb',
            'amount_bytes',
            'amount_gb',
            'adjustment_id',
            'status',
            'description',
            'created_at'
        ]
        read_only_fields = ['id', 'created_at']

    def get_amount_gb(self, obj):
        """Convert bytes to GB for display."""
        return round(obj.amount_bytes / (1024 ** 3), 2) if obj.amount_bytes else 0


class TopUpBalanceSerializer(serializers.Serializer):
    """Serializer for manual balance top-up."""
    amount_bytes = serializers.IntegerField(
        min_value=1,
        help_text="Amount to add in bytes"
    )
    description = serializers.CharField(
        max_length=255,
        required=False,
        allow_blank=True,
        default="Manual balance top-up",
        help_text="Description for the top-up"
    )


class SyncOfferingsSerializer(serializers.Serializer):
    """Serializer for syncing offerings from OCS server."""
    ocs_instance_pk = serializers.IntegerField(
        help_text="Primary key of the OCS instance to sync from"
    )
    overwrite_existing = serializers.BooleanField(
        default=False,
        help_text="Whether to overwrite existing offerings with same offering_id"
    )

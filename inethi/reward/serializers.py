from rest_framework import serializers
from .models import Reward, UptimeRewardTransaction
from transaction.serializers import TransactionSerializer


class RewardSerializer(serializers.ModelSerializer):
    """Serializer for rewards"""

    interval_minutes = serializers.IntegerField(
        required=False,
        allow_null=True,  # Allow it to be null for one-time rewards
        help_text="Interval for recurring rewards in minutes"
    )

    class Meta:
        model = Reward
        fields = [
            'id', 'name', 'user',
            'device', 'reward_type', 'reward_amount',
            'is_cancelled', 'created_at', 'once_off',
            'celery_task_id', 'interval_minutes', 'network'
        ]
        read_only_fields = ['id', 'created_at', 'celery_task_id']

    def create(self, validated_data):
        """Create a new reward and store the interval_minutes correctly"""
        interval_minutes = validated_data.pop('interval_minutes', None)
        reward = Reward.objects.create(**validated_data)

        if not reward.once_off and interval_minutes:
            reward.interval_minutes = interval_minutes
            reward.save()

        return reward

    def update(self, instance, validated_data):
        """Update a reward and store interval_minutes correctly"""
        interval_minutes = validated_data.get(
            'interval_minutes',
            instance.interval_minutes
        )

        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        instance.interval_minutes = interval_minutes
        instance.save()
        return instance


class UptimeRewardTransactionSerializer(serializers.ModelSerializer):
    """Serializer for uptime reward transactions"""

    transaction = TransactionSerializer(read_only=True)
    reward = RewardSerializer(read_only=True)

    class Meta:
        model = UptimeRewardTransaction
        fields = '__all__'


class RewardFilterSerializer(serializers.Serializer):
    """Serializer for filtering rewards"""

    user_id = serializers.IntegerField(
        required=False,
        help_text="Filter by user ID"
    )
    reward_type = serializers.ChoiceField(
        choices=Reward.REWARD_TYPE_CHOICES,
        required=False,
        help_text="Filter by reward type"
    )

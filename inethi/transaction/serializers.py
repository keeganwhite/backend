from rest_framework import serializers
from core.models import Transaction
from django.contrib.auth import get_user_model

User = get_user_model()


class UserSerializer(
    serializers.ModelSerializer
):
    """Serializer for the user"""
    class Meta:
        model = User
        fields = ['username']


class TransactionSerializer(
    serializers.ModelSerializer
):
    """Serializer for the transaction"""
    sender = UserSerializer(read_only=True, allow_null=True)
    recipient = UserSerializer(read_only=True, allow_null=True)

    class Meta:
        model = Transaction
        fields = '__all__'
        read_only_fields = [
            'transaction_hash',
            'block_number',
            'gas_used',
            'timestamp',
            'amount'
        ]

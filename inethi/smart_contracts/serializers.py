from rest_framework import serializers
from core.models import (
    SmartContract,
    FaucetSmartContract,
    AccountsIndexContract
)


class BaseSmartContractSerializer(serializers.ModelSerializer):
    """Base serializer for SmartContract model without to_representation"""
    contract_type = serializers.CharField()

    class Meta:
        model = SmartContract
        fields = [
            'id',
            'name',
            'address',
            'description',
            'user',
            'write_access',
            'read_access',
            'contract_type',
        ]


class SmartContractSerializer(BaseSmartContractSerializer):
    """
    Serializer for SmartContract model
     with dynamic subclass serialization
     """

    def to_representation(self, instance):
        instance = instance.get_child_instance()
        if isinstance(instance, FaucetSmartContract):
            return FaucetSmartContractSerializer(
                instance,
                context=self.context
            ).data
        elif isinstance(instance, AccountsIndexContract):
            return AccountsIndexContractSerializer(
                instance,
                context=self.context
            ).data
        else:
            return super(
                BaseSmartContractSerializer,
                self
            ).to_representation(instance)


class FaucetSmartContractSerializer(BaseSmartContractSerializer):
    """Serializer for FaucetSmartContract model"""

    class Meta(BaseSmartContractSerializer.Meta):
        model = FaucetSmartContract
        fields = BaseSmartContractSerializer.Meta.fields + [
            'gimme',
            'give_to',
            'next_balance',
            'next_time',
            'registry_address',
        ]


class AccountsIndexContractSerializer(BaseSmartContractSerializer):
    """Serializer for AccountsIndexContract model"""

    class Meta(BaseSmartContractSerializer.Meta):
        model = AccountsIndexContract
        fields = BaseSmartContractSerializer.Meta.fields + [
            'owner_address',
            'entry',
            'entry_count',
            'is_active',
            'activate',
            'deactivate',
            'add',
            'remove',
        ]

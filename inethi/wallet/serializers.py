from rest_framework import serializers
from core.models import Wallet
from utils.crypto import CryptoUtils, encrypt_private_key, decrypt_private_key
from django.conf import settings


class WalletSerializer(serializers.ModelSerializer):
    """Serializer for Wallet Model"""

    class Meta:
        model = Wallet
        fields = [
            'name', 'address', 'token_common_name', 'token', 'id'
        ]
        read_only_fields = [
            'user', 'private_key', 'address', 'token_common_name',
            'token', 'token_type', 'created_at', 'id'
        ]

    def create(self, validated_data):
        """
        Create a new wallet, generate private key,
        encrypt it, add it to the account index and
        set immutable fields
        """

        # Use utility script to create wallet
        crypto_utils = CryptoUtils(
            contract_abi_path=settings.ABI_FILE_PATH,
            contract_address=settings.CONTRACT_ADDRESS,
            registry=settings.FAUCET_AND_INDEX_ENABLED
        )
        wallet_info = crypto_utils.create_wallet()

        # Ensure wallet_info contains the expected keys
        if 'private_key' not in wallet_info or 'address' not in wallet_info:
            raise serializers.ValidationError(
                "Wallet creation failed: missing keys in response"
            )

        p_key = wallet_info['private_key']
        w_addr = wallet_info['address']
        encrypted_private_key = encrypt_private_key(p_key)

        wallet_data = {
            'user': validated_data['user'],
            'name': validated_data.get('name', 'default_name'),
            'private_key': encrypted_private_key,
            'address': w_addr,
            'token_common_name': 'KRONE',
            'token': 'KRONE',
            'token_type': 'ERC-20',
        }

        if settings.FAUCET_AND_INDEX_ENABLED:
            # Add the wallet to the account index for Krone
            account_index_creator = Wallet.objects.get(
                address=settings.ACCOUNT_INDEX_ADMIN_WALLET_ADDRESS
            )
            p_key = decrypt_private_key(account_index_creator.private_key)
            crypto_utils.registry_add(
                private_key=p_key,
                address_to_add=w_addr,
            )

        # Create the wallet
        return Wallet.objects.create(**wallet_data)

    def update(self, instance, validated_data):
        """
        Ensure only mutable fields like 'name' can be updated
        """
        # Only allow updating the 'name' field
        instance.name = validated_data.get('name', instance.name)
        instance.save()

        return instance

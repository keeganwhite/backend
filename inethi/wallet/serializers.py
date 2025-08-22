from rest_framework import serializers
from core.models import Wallet
from utils.crypto import CryptoUtils, encrypt_private_key, decrypt_private_key
from django.conf import settings
import logging

logger = logging.getLogger(__name__)


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
            registry=settings.FAUCET_AND_INDEX_ENABLED,
            faucet=settings.FAUCET_AND_INDEX_ENABLED,
        )
        wallet_info = crypto_utils.create_wallet()

        # Ensure wallet_info contains the expected keys
        if 'private_key' not in wallet_info or 'address' not in wallet_info:
            logger.error("Wallet creation failed: missing keys in response")
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
        logger.info(f"Wallet data: {wallet_data}")

        if settings.FAUCET_AND_INDEX_ENABLED:
            try:
                # Add the wallet to the account index for Krone
                account_index_creator = Wallet.objects.get(  # type: ignore[attr-defined]
                    address=settings.ACCOUNT_INDEX_ADMIN_WALLET_ADDRESS
                )
                p_key_admin = decrypt_private_key(account_index_creator.private_key)

                # Create new CryptoUtils instance for registry operations
                registry_crypto = CryptoUtils(
                    contract_abi_path=settings.ABI_FILE_PATH,
                    contract_address=settings.CONTRACT_ADDRESS,
                    registry=settings.FAUCET_AND_INDEX_ENABLED,
                    faucet=settings.FAUCET_AND_INDEX_ENABLED,
                )
                registry_crypto.registry_add(p_key_admin, w_addr)

                # send the account gas
                faucet_creator = Wallet.objects.get(  # type: ignore[attr-defined]
                    address=settings.FAUCET_ADMIN_WALLET_ADDRESS
                )
                p_key_faucet = decrypt_private_key(faucet_creator.private_key)

                # Create new CryptoUtils instance for faucet operations
                faucet_crypto = CryptoUtils(
                    contract_abi_path=settings.ABI_FILE_PATH,
                    contract_address=settings.CONTRACT_ADDRESS,
                    registry=settings.FAUCET_AND_INDEX_ENABLED,
                    faucet=settings.FAUCET_AND_INDEX_ENABLED,
                )
                faucet_crypto.faucet_give_to(p_key_faucet, w_addr)
            except Exception as e:
                logger.error(
                    f"Error during wallet creation (registry/faucet): {e}"
                )
                raise serializers.ValidationError(
                    f"Wallet creation failed: {e}"
                )

        # Create the wallet
        return Wallet.objects.create(   # type: ignore[attr-defined]
            **wallet_data
        )

    def update(self, instance, validated_data):
        """
        Ensure only mutable fields like 'name' can be updated
        """
        # Only allow updating the 'name' field
        instance.name = validated_data.get('name', instance.name)
        instance.save()

        return instance

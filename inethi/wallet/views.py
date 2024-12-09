from rest_framework import viewsets, permissions, status
from rest_framework.response import Response
from rest_framework.decorators import action

import utils.crypto
from core.models import Wallet, User, Transaction
from utils.crypto import CryptoUtils
from utils.keycloak import KeycloakAuthentication
from .serializers import WalletSerializer
from rest_framework.exceptions import PermissionDenied
from django.conf import settings

from utils.crypto import decrypt_private_key


class WalletViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing wallets. Supports creating, sending tokens,
    checking if a user has a wallet, updating, and deleting a wallet.
    """
    serializer_class = WalletSerializer
    authentication_classes = (KeycloakAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)
    crypto_utils = CryptoUtils(
        contract_abi_path=settings.ABI_FILE_PATH,
        contract_address=settings.CONTRACT_ADDRESS,
        registry=settings.FAUCET_AND_INDEX_ENABLED,
        faucet=settings.FAUCET_AND_INDEX_ENABLED,
    )

    def get_queryset(self):
        """
        Restrict the queryset to the wallets owned by the authenticated user.
        """
        return Wallet.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        """Create a new wallet."""
        serializer.save(user=self.request.user)

    def get_serializer_class(self):
        """Return the serializer class for request."""
        return self.serializer_class

    def perform_update(self, serializer):
        """
        Ensure the user can only update their own wallet.
        """
        wallet = self.get_object()
        if wallet.user != self.request.user:
            raise PermissionDenied("You cannot update someone else's wallet.")
        serializer.save()

    def perform_destroy(self, instance):
        """
        Ensure the user can only delete their own wallet.
        """
        if instance.user != self.request.user:
            raise PermissionDenied("You cannot delete someone else's wallet.")
        instance.delete()

    @action(detail=False, methods=['get'], url_path='has-wallet')
    def has_wallet(self, request):
        """
        Check if the authenticated user has a wallet.
        """
        wallet_exists = Wallet.objects.filter(user=request.user).exists()
        return Response(
            {'has_wallet': wallet_exists},
            status=status.HTTP_200_OK
        )

    @action(detail=False, methods=['get'], url_path='user-wallet-details')
    def user_wallet_details(self, request):
        """Get the authenticated user's wallet details."""
        wallet = Wallet.objects.filter(user=request.user).first()

        if wallet:
            serializer = WalletSerializer(wallet)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(
                {
                    'detail': 'Wallet not found.'
                },
                status=status.HTTP_404_NOT_FOUND
            )

    @action(detail=True, methods=['post'], url_path='send-token')
    def send_token(self, request, pk=None):
        """
        Send tokens to another wallet.
        Requires 'recipient_address' and 'amount'.
        """
        wallet = self.get_object()  # auto calls with pk
        if wallet.user != request.user:
            raise PermissionDenied(
                "You cannot send tokens from someone else's wallet."
            )

        # Validate recipient address and amount
        recipient_address = request.data.get('recipient_address')
        amount = request.data.get('amount')

        if not recipient_address or not amount:
            return Response(
                {'error': 'Recipient address and amount are required.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:

            # Decrypt the private key
            decrypted_private_key = utils.crypto.decrypt_private_key(
                wallet.private_key
            )
            # ensure account has gas if we can give them gas
            if settings.FAUCET_AND_INDEX_ENABLED:
                faucet_creator = Wallet.objects.get(
                    address=settings.ACCOUNT_INDEX_ADMIN_WALLET_ADDRESS
                )
                p_key = decrypt_private_key(faucet_creator.private_key)
                self.crypto_utils.pre_transaction_check(
                    private_key_admin=p_key,
                    from_address=wallet.address,
                    to_address=recipient_address,
                    amount=float(amount)
                )
            # Send tokens using CryptoUtils
            tx_receipt = self.crypto_utils.send_to_wallet_address(
                wallet.address,
                decrypted_private_key,
                recipient_address,
                float(amount)
            )
            tx_receipt_dict = {
                'transactionHash': tx_receipt.transactionHash.hex(),
                'blockHash': tx_receipt.blockHash.hex(),
                'blockNumber': tx_receipt.blockNumber,
                'gasUsed': tx_receipt.gasUsed,
                'status': tx_receipt.status,
                'transactionIndex': tx_receipt.transactionIndex
            }
            # create transaction
            Transaction.objects.create(
                sender=request.user,
                recipient_address=recipient_address,
                amount=float(amount),
                block_hash=tx_receipt.blockHash.hex(),
                transaction_hash=tx_receipt.transactionHash.hex(),
                block_number=tx_receipt.blockNumber,
                gas_used=tx_receipt.gasUsed,
                category='Transfer'
            )

            return Response(
                {'transaction_receipt': tx_receipt_dict},
                status=status.HTTP_200_OK
            )
        except Exception as e:
            return (Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            ))

    @action(detail=True, methods=['post'], url_path='send-token-username')
    def send_token_pk_username(self, request, pk=None):
        """
        Send tokens to another wallet.
        Requires 'username' and 'amount'.
        """
        wallet = self.get_object()  # auto calls with pk
        if wallet.user != request.user:
            raise PermissionDenied(
                "You cannot send tokens from someone else's wallet."
            )

        # Validate recipient address and amount
        username = request.data.get('username')
        amount = request.data.get('amount')

        if not username or not amount:
            return Response(
                {'error': 'Recipient address and amount are required.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        receiver_exists = User.objects.filter(username=username).exists()
        if not receiver_exists:
            return Response(
                {
                    'detail': 'Recipient username not found.'
                },
                status=status.HTTP_404_NOT_FOUND
            )
        receiver = User.objects.get(username=username)
        receiver_wallet_exists = Wallet.objects.filter(user=receiver).exists()

        if not receiver_wallet_exists:
            return Response(
                {
                    'detail': 'Recipient Wallet not found.'
                },
                status=status.HTTP_404_NOT_FOUND
            )
        receiver_wallet = Wallet.objects.filter(user=receiver).first()
        recipient_address = receiver_wallet.address

        try:

            # Decrypt the private key
            decrypted_private_key = utils.crypto.decrypt_private_key(
                wallet.private_key
            )
            # ensure account has gas if we can give them gas
            if settings.FAUCET_AND_INDEX_ENABLED:
                faucet_creator = Wallet.objects.get(
                    address=settings.ACCOUNT_INDEX_ADMIN_WALLET_ADDRESS
                )
                p_key = decrypt_private_key(faucet_creator.private_key)
                self.crypto_utils.pre_transaction_check(
                    private_key_admin=p_key,
                    from_address=wallet.address,
                    to_address=recipient_address,
                    amount=float(amount)
                )
            # Send tokens using CryptoUtils
            tx_receipt = self.crypto_utils.send_to_wallet_address(
                wallet.address,
                decrypted_private_key,
                recipient_address,
                float(amount)
            )
            tx_receipt_dict = {
                'transactionHash': tx_receipt.transactionHash.hex(),
                'blockHash': tx_receipt.blockHash.hex(),
                'blockNumber': tx_receipt.blockNumber,
                'gasUsed': tx_receipt.gasUsed,
                'status': tx_receipt.status,
                'transactionIndex': tx_receipt.transactionIndex
            }

            # create transaction
            Transaction.objects.create(
                sender=request.user,
                recipient=receiver,
                recipient_address=recipient_address,
                amount=float(amount),
                block_hash=tx_receipt.blockHash.hex(),
                transaction_hash=tx_receipt.transactionHash.hex(),
                block_number=tx_receipt.blockNumber,
                gas_used=tx_receipt.gasUsed,
                category='Transfer'
            )

            return Response(
                {'transaction_receipt': tx_receipt_dict},
                status=status.HTTP_200_OK
            )
        except Exception as e:
            return (Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            ))

    @action(detail=False, methods=['post'], url_path='send-token-by-address')
    def send_token_user_address(self, request):
        """
        Send tokens to another wallet.
        Requires 'recipient_address' and 'amount'.
        """
        wallet_exists = Wallet.objects.filter(user=request.user).exists()
        if not wallet_exists:
            return Response(
                {
                    'detail': 'Wallet not found.'
                },
                status=status.HTTP_404_NOT_FOUND
            )
        wallet = Wallet.objects.filter(user=request.user).first()
        # Validate recipient address and amount
        recipient_address = request.data.get('recipient_address')
        amount = request.data.get('amount')

        if not recipient_address or not amount:
            return Response(
                {'error': 'Recipient address and amount are required.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Decrypt the private key
            decrypted_private_key = utils.crypto.decrypt_private_key(
                wallet.private_key
            )
            # Send tokens using CryptoUtils
            tx_receipt = self.crypto_utils.send_to_wallet_address(
                wallet.address,
                decrypted_private_key,
                recipient_address,
                float(amount)
            )
            tx_receipt_dict = {
                'transactionHash': tx_receipt.transactionHash.hex(),
                'blockHash': tx_receipt.blockHash.hex(),
                'blockNumber': tx_receipt.blockNumber,
                'gasUsed': tx_receipt.gasUsed,
                'status': tx_receipt.status,
                'transactionIndex': tx_receipt.transactionIndex
            }

            return Response(
                {'transaction_receipt': tx_receipt_dict},
                status=status.HTTP_200_OK
            )
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(detail=False, methods=['post'], url_path='send-token-by-username')
    def send_token_username(self, request):
        """
        Send tokens to another wallet.
        Requires 'username' and 'amount'.
        """
        amount = request.data.get('amount')
        username = request.data.get('username')
        print(username, amount)
        client_wallet_exists = Wallet.objects.filter(
            user=request.user
        ).exists()
        if not client_wallet_exists:
            return Response(
                {
                    'detail': 'Wallet not found.'
                },
                status=status.HTTP_404_NOT_FOUND
            )

        wallet = Wallet.objects.filter(user=request.user).first()

        receiver_exists = User.objects.filter(username=username).exists()
        if not receiver_exists:
            return Response(
                {
                    'detail': 'Recipient username not found.'
                },
                status=status.HTTP_404_NOT_FOUND
            )
        receiver = User.objects.get(username=username)
        receiver_wallet_exists = Wallet.objects.filter(user=receiver).exists()

        if not receiver_wallet_exists:
            return Response(
                {
                    'detail': 'Recipient Wallet not found.'
                },
                status=status.HTTP_404_NOT_FOUND
            )
        receiver_wallet = Wallet.objects.filter(user=receiver).first()
        recipient_address = receiver_wallet.address

        try:
            # Decrypt the private key
            decrypted_private_key = utils.crypto.decrypt_private_key(
                wallet.private_key
            )
            # Send tokens using CryptoUtils
            tx_receipt = self.crypto_utils.send_to_wallet_address(
                wallet.address,
                decrypted_private_key,
                recipient_address,
                float(amount)
            )
            tx_receipt_dict = {
                'transactionHash': tx_receipt.transactionHash.hex(),
                'blockHash': tx_receipt.blockHash.hex(),
                'blockNumber': tx_receipt.blockNumber,
                'gasUsed': tx_receipt.gasUsed,
                'status': tx_receipt.status,
                'transactionIndex': tx_receipt.transactionIndex
            }

            return Response(
                {'transaction_receipt': tx_receipt_dict},
                status=status.HTTP_200_OK
            )
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(detail=False, methods=['get'], url_path='wallet-balance')
    def user_wallet_balance(self, request):
        """Get the authenticated user's wallet details."""
        wallet = Wallet.objects.filter(user=request.user).first()

        if wallet:
            token_name = wallet.token_common_name
            if token_name == 'KRONE':
                balance = self.crypto_utils.balance_of(wallet.address)
                return Response(
                    {'balance': balance},
                    status=status.HTTP_200_OK
                )
        return Response(
            {'detail': 'Wallet not found.'}, status=status.HTTP_404_NOT_FOUND
        )

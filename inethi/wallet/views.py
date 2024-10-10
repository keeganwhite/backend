from rest_framework import viewsets, permissions, status
from rest_framework.response import Response
from rest_framework.decorators import action

import utils.crypto
from core.models import Wallet
from utils.crypto import CryptoUtils
from utils.keycloak import KeycloakAuthentication
from .serializers import WalletSerializer
from rest_framework.exceptions import PermissionDenied
from django.conf import settings


class WalletViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing wallets. Supports creating, sending tokens,
    checking if a user has a wallet, updating, and deleting a wallet.
    """
    serializer_class = WalletSerializer
    authentication_classes = (KeycloakAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)

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
            crypto_utils = CryptoUtils(
                contract_abi_path=settings.ABI_FILE_PATH,
                contract_address=settings.CONTRACT_ADDRESS,
                registry=settings.FAUCET_AND_INDEX_ENABLED,
            )
            # Decrypt the private key
            decrypted_private_key = utils.crypto.decrypt_private_key(
                wallet.private_key
            )
            # Send tokens using CryptoUtils
            tx_receipt = crypto_utils.send_to_wallet_address(
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

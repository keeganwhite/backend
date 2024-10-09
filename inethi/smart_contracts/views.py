from django.conf import settings
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response

from core.models import (
    Wallet,
    SmartContract,
    FaucetSmartContract,
    AccountsIndexContract
)
from utils.keycloak import KeycloakAuthentication
from .serializers import (
    SmartContractSerializer,
    FaucetSmartContractSerializer,
    AccountsIndexContractSerializer
)
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.exceptions import ValidationError

from utils.crypto import decrypt_private_key, CryptoUtils


class SmartContractViewSet(viewsets.ModelViewSet):
    """ViewSet for Smart Contracts"""
    serializer_class = SmartContractSerializer
    authentication_classes = (KeycloakAuthentication,)
    permission_classes = (IsAuthenticated,)
    queryset = SmartContract.objects.all()
    c_utils = CryptoUtils(
        contract_abi_path=settings.ABI_FILE_PATH,
        contract_address=settings.CONTRACT_ADDRESS,
        registry=True
    )

    def get_permissions(self):
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            # Only admin users can perform write operations
            permission_classes = [IsAdminUser]
        else:
            # Anyone can read
            permission_classes = [IsAuthenticated]
        return [permission() for permission in permission_classes]

    def get_serializer_class(self):
        if self.action == 'retrieve':
            if 'pk' in getattr(self, 'kwargs', {}):
                instance = self.get_object()
                if isinstance(instance, FaucetSmartContract):
                    return FaucetSmartContractSerializer
                elif isinstance(instance, AccountsIndexContract):
                    return AccountsIndexContractSerializer
            return SmartContractSerializer
        elif self.action == 'list':
            return SmartContractSerializer
        elif self.action in ['create', 'update', 'partial_update']:
            contract_type = self.request.data.get(
                'contract_type'
            ) if self.request else None
            if contract_type == 'eth faucet':
                return FaucetSmartContractSerializer
            elif contract_type == 'account index':
                return AccountsIndexContractSerializer
            return SmartContractSerializer
        else:
            return SmartContractSerializer

    def create(self, request, *args, **kwargs):
        contract_type = request.data.get('contract_type')
        if contract_type == 'eth faucet':
            serializer_class = FaucetSmartContractSerializer
        elif contract_type == 'account index':
            serializer_class = AccountsIndexContractSerializer
        else:
            serializer_class = SmartContractSerializer

        serializer = serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(
            serializer.data,
            status=status.HTTP_201_CREATED,
            headers=headers
        )

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        contract_type = request.data.get(
            'contract_type', instance.contract_type
        )
        if contract_type != instance.contract_type:
            raise ValidationError(
                {'contract_type': 'You cannot change the contract type.'}
            )

        if isinstance(instance, FaucetSmartContract):
            serializer_class = FaucetSmartContractSerializer
        elif isinstance(instance, AccountsIndexContract):
            serializer_class = AccountsIndexContractSerializer
        else:
            serializer_class = SmartContractSerializer

        partial = kwargs.pop('partial', False)
        serializer = serializer_class(
            instance,
            data=request.data,
            partial=partial
        )
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data)

    @action(detail=True, methods=['post'], url_path='registry-add')
    def registry_add(self, request, pk=None):
        """Call the add method for an account index"""
        contract = SmartContract.objects.get(pk=pk)
        contract_type = contract.contract_type

        if contract_type != 'account index':
            return Response(
                {
                    'contract_type':
                        'You cannot be added to this contract type.'
                 },
                status=status.HTTP_400_BAD_REQUEST
            )

        account_index_contract = AccountsIndexContract.objects.get(pk=pk)
        add_function = account_index_contract.add
        owner_addr = account_index_contract.owner_address

        if not add_function:
            return Response(
                {'error': 'There is no add function for this smart contract.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if (not contract.write_access or
                owner_addr != settings.ACCOUNT_INDEX_ADMIN_WALLET_ADDRESS):
            return Response(
                {'error': 'This is not an iNethi smart contract.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        user_wallet_addr = request.data['address']
        wallet_exists = Wallet.objects.filter(
            user=request.user,
            address=user_wallet_addr
        ).exists()

        if wallet_exists:
            wallet = Wallet.objects.get(
                user=request.user,
                address=user_wallet_addr
            )
            add_address = wallet.address
            account_index_creator = Wallet.objects.get(
                address=settings.ACCOUNT_INDEX_ADMIN_WALLET_ADDRESS
            )
            p_key = decrypt_private_key(account_index_creator.private_key)
            receipt = self.c_utils.registry_add(
                private_key=p_key,
                address_to_add=add_address,
            )
            if isinstance(receipt, dict):
                receipt_data = receipt
            else:
                receipt_data = {
                    'transactionHash': receipt.transactionHash.hex(),
                    'blockHash': receipt.blockHash.hex(),
                    'blockNumber': receipt.blockNumber,
                    'gasUsed': receipt.gasUsed,
                    'status': receipt.status,
                    'transactionIndex': receipt.transactionIndex,
                }

            return Response(
                status=status.HTTP_200_OK,
                data={'transaction_receipt': receipt_data},
            )

            return Response(
                status=status.HTTP_200_OK,
                data={'transaction_receipt': receipt},
            )

        else:
            return Response(
                {'error': 'No wallet found for the provided user.'},
                status=status.HTTP_400_BAD_REQUEST
            )

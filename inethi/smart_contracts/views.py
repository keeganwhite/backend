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
    # CryptoUtils will be created per transaction to avoid nonce conflicts

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

    def list(self, request, *args, **kwargs):
        """
        List all contracts or filter by contract type.
        """
        contract_type = request.query_params.get('contract_type')
        if contract_type:
            self.queryset = self.queryset.filter(contract_type=contract_type)
        return super().list(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        """
        Retrieve a specific contract by primary key.
        """
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data)

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

    @action(
        detail=True,
        methods=['post'],
        url_path='registry-add',
        permission_classes=[IsAdminUser]
    )
    def registry_add(self, request, pk=None):
        """
        This endpoint allows an iNethi
        Krone user to join the accounts index
        """

        # Make sure the user has admin privileges first
        if not request.user.is_staff:
            return Response(
                {
                    'error':
                        'You do not have permission to perform this action.'
                },
                status=status.HTTP_401_UNAUTHORIZED
            )

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
            address=user_wallet_addr
        ).exists()

        if wallet_exists:
            wallet = Wallet.objects.get(
                address=user_wallet_addr
            )
            add_address = wallet.address
            account_index_creator = Wallet.objects.get(
                address=settings.ACCOUNT_INDEX_ADMIN_WALLET_ADDRESS
            )
            p_key = decrypt_private_key(account_index_creator.private_key)
            # Create new CryptoUtils instance for registry operations
            crypto_utils = CryptoUtils(
                contract_abi_path=settings.ABI_FILE_PATH,
                contract_address=settings.CONTRACT_ADDRESS,
                registry=settings.FAUCET_AND_INDEX_ENABLED,
                faucet=settings.FAUCET_AND_INDEX_ENABLED,
            )
            receipt = crypto_utils.registry_add(p_key, add_address)
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

        else:
            return Response(
                {'error': 'No wallet found for the provided user.'},
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(
        detail=True,
        methods=['post'],
        url_path='faucet-give-to',
        permission_classes=[IsAdminUser]
    )
    def faucet_give_to(self, request, pk=None):
        """
        Send tokens to an address from a faucet
        ---
        Required fields:
        - address: The wallet address to send tokens to.
        """
        contract = SmartContract.objects.get(pk=pk)

        # Make sure the user has admin privileges first
        if not request.user.is_staff:
            return Response(
                {
                    'error':
                        'You do not have permission to perform this action.'
                },
                status=status.HTTP_401_UNAUTHORIZED
            )
        contract_type = contract.contract_type

        if contract_type != 'eth faucet':
            return Response(
                {
                    'contract_type':
                        'You cannot giveTo for this type of contract.'
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        faucet_contract = FaucetSmartContract.objects.get(pk=pk)
        give_to_function = faucet_contract.give_to
        owner_addr = faucet_contract.owner_address

        if not give_to_function:
            return Response(
                {
                    'error':
                        'There is no giveTo function for this smart contract.'
                },
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
            address=user_wallet_addr
        ).exists()

        if wallet_exists:
            wallet = Wallet.objects.get(
                address=user_wallet_addr
            )
            give_to_addr = wallet.address

            faucet_creator = Wallet.objects.get(
                address=settings.ACCOUNT_INDEX_ADMIN_WALLET_ADDRESS
            )
            p_key = decrypt_private_key(faucet_creator.private_key)

            # Create new CryptoUtils instance for faucet operations
            crypto_utils = CryptoUtils(
                contract_abi_path=settings.ABI_FILE_PATH,
                contract_address=settings.CONTRACT_ADDRESS,
                registry=settings.FAUCET_AND_INDEX_ENABLED,
                faucet=settings.FAUCET_AND_INDEX_ENABLED,
            )
            receipt = crypto_utils.faucet_give_to(p_key, give_to_addr)

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

        else:
            return Response(
                {'error': 'No wallet found for the provided user.'},
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(
        detail=True,
        methods=['post'],
        url_path='registry-check-active',
        permission_classes=[IsAuthenticated]
    )
    def registry_check_active(self, request, pk=None):
        """
        Check if a wallet address is active in an account index
        ---
        Required fields:
        - address: The wallet address to check status.
        """
        contract = SmartContract.objects.get(pk=pk)
        contract_type = contract.contract_type

        if contract_type != 'account index':
            return Response(
                {
                    'contract_type':
                        'You cannot check active '
                        'status for this contract type.'
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        account_index_contract = AccountsIndexContract.objects.get(pk=pk)
        active_func = account_index_contract.is_active

        if not active_func:
            return Response(
                {
                    'error':
                        'There is no isActive function '
                        'for this smart contract.'
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        wallet_addr = request.data['address']
        # Create new CryptoUtils instance for balance check
        crypto_utils = CryptoUtils(
            contract_abi_path=settings.ABI_FILE_PATH,
            contract_address=settings.CONTRACT_ADDRESS,
            registry=settings.FAUCET_AND_INDEX_ENABLED,
            faucet=settings.FAUCET_AND_INDEX_ENABLED,
        )
        active = crypto_utils.account_index_check_active(wallet_addr)

        return Response(
            status=status.HTTP_200_OK,
            data={'is_active': active},
        )

    @action(
        detail=True,
        methods=['post'],
        url_path='faucet-gimme',
        permission_classes=[IsAuthenticated]
    )
    def faucet_gimme(self, request, pk=None):
        """Ask for gas from the faucet"""
        contract = SmartContract.objects.get(pk=pk)
        contract_type = contract.contract_type

        if contract_type != 'eth faucet':
            return Response(
                {
                    'error':
                        'No gimme function for this contract type.'
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        eth_faucet = FaucetSmartContract.objects.get(pk=pk)
        gimme_func = eth_faucet.gimme

        if not gimme_func:
            return Response(
                {
                    'error':
                        'There is no gimme function for this smart contract.'
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        wallet_exists = Wallet.objects.filter(user=request.user).exists()
        if wallet_exists:
            try:
                wallet = Wallet.objects.get(user=request.user)

                decrypted_private_key = decrypt_private_key(
                    wallet.private_key
                )

                # Create new CryptoUtils instance for faucet operations
                crypto_utils = CryptoUtils(
                    contract_abi_path=settings.ABI_FILE_PATH,
                    contract_address=settings.CONTRACT_ADDRESS,
                    registry=settings.FAUCET_AND_INDEX_ENABLED,
                    faucet=settings.FAUCET_AND_INDEX_ENABLED,
                )

                # Call faucet gimme (new method returns transaction receipt)
                receipt = crypto_utils.faucet_gimme(decrypted_private_key, wallet.address)

                # For now, return success since the new method doesn't return detailed info
                # You may want to add additional checks here if needed
                return Response(
                    {
                        'success': True,
                        'transaction_hash': receipt.transactionHash.hex(),
                        'gas_used': receipt.gasUsed
                    },
                    status=status.HTTP_200_OK
                )

            except Exception as e:
                return Response(
                    {
                        'error': f'Failed to call gimme: {e}.'
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

        else:
            return Response(
                {'error': 'No wallet found for this user.'},
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(
        detail=True,
        methods=['post'],
        url_path='faucet-next-time',
        permission_classes=[IsAuthenticated]
    )
    def faucet_next_time(self, request, pk=None):
        """Check the time until you can request again"""
        contract = SmartContract.objects.get(pk=pk)
        contract_type = contract.contract_type

        if contract_type != 'eth faucet':
            return Response(
                {
                    'error':
                        'No nextTime function for this contract type.'
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        eth_faucet = FaucetSmartContract.objects.get(pk=pk)
        next_time = eth_faucet.next_time

        if not next_time:
            return Response(
                {
                    'error':
                        'There is no nextTime function '
                        'for this smart contract.'
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        wallet_exists = Wallet.objects.filter(user=request.user).exists()
        if wallet_exists:
            wallet = Wallet.objects.get(user=request.user)
            address = wallet.address

            # Create new CryptoUtils instance for faucet operations
            crypto_utils = CryptoUtils(
                contract_abi_path=settings.ABI_FILE_PATH,
                contract_address=settings.CONTRACT_ADDRESS,
                registry=settings.FAUCET_AND_INDEX_ENABLED,
                faucet=settings.FAUCET_AND_INDEX_ENABLED,
            )
            get_next_time = crypto_utils.faucet_check_time(address)
            return Response(
                {
                    'can_request': get_next_time['is_older'],
                    'time_stamp': get_next_time['time_stamp'],
                },
                status=status.HTTP_200_OK
            )
        else:
            return Response(
                {'error': 'No wallet found for this user.'},
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(
        detail=True,
        methods=['post'],
        url_path='faucet-balance',
        permission_classes=[IsAuthenticated]
    )
    def faucet_balance(self, request, pk=None):
        """Check what the balance threshold is."""
        contract = SmartContract.objects.get(pk=pk)
        contract_type = contract.contract_type

        if contract_type != 'eth faucet':
            return Response(
                {
                    'error':
                        'No balance function for this contract type.'
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        eth_faucet = FaucetSmartContract.objects.get(pk=pk)
        next_time = eth_faucet.next_balance

        if not next_time:
            return Response(
                {
                    'error':
                        'There is no balance function for this smart contract.'
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        wallet_exists = Wallet.objects.filter(user=request.user).exists()
        if wallet_exists:
            wallet = Wallet.objects.get(user=request.user)
            address = wallet.address

            # Create new CryptoUtils instance for faucet operations
            crypto_utils = CryptoUtils(
                contract_abi_path=settings.ABI_FILE_PATH,
                contract_address=settings.CONTRACT_ADDRESS,
                registry=settings.FAUCET_AND_INDEX_ENABLED,
                faucet=settings.FAUCET_AND_INDEX_ENABLED,
            )
            balance_thresh = crypto_utils.faucet_balance_threshold(address)
            return Response(
                {
                    'amount': balance_thresh,
                },
                status=status.HTTP_200_OK
            )
        else:
            return Response(
                {'error': 'No wallet found for this user.'},
                status=status.HTTP_400_BAD_REQUEST
            )

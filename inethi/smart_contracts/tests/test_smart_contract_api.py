from unittest.mock import patch
from django.urls import reverse
from django.test import TestCase
from django.conf import settings
from rest_framework.test import APIClient
from rest_framework import status

from core.models import (
    SmartContract,
    FaucetSmartContract,
    AccountsIndexContract,
    Wallet,
)
from django.contrib.auth import get_user_model

from utils.crypto import encrypt_private_key

# URLs for the API endpoints
SMART_CONTRACT_URL = reverse('smartcontract:smartcontract-list')


def detail_url(smart_contract_id):
    """Return smart contract detail URL"""
    return reverse(
        'smartcontract:smartcontract-detail',
        args=[smart_contract_id]
    )


def registry_add_url(smart_contract_id):
    """Return URL for the registry_add action"""
    return reverse(
        'smartcontract:smartcontract-registry-add',
        args=[smart_contract_id]
    )


def faucet_give_to_url(smart_contract_id):
    """Return URL for the faucet give to action"""
    return reverse(
        'smartcontract:smartcontract-faucet-give-to',
        args=[smart_contract_id]
    )


def registry_is_active_url(smart_contract_id):
    """Return URL for the is_active action"""
    return reverse(
        'smartcontract:smartcontract-registry-check-active',
        args=[smart_contract_id]
    )


def create_user(**params):
    """Helper function to create a user"""
    return get_user_model().objects.create_user(**params)


def create_smart_contract(user, **params):
    """Helper function to create a smart contract"""
    defaults = {
        'name': 'Test Contract',
        'address': '0x1234567890abcdef',
        'description': 'Test Description',
        'write_access': True,
        'read_access': True,
        'contract_type': 'eth faucet',
    }
    defaults.update(params)
    return SmartContract.objects.create(user=user, **defaults)


class PublicSmartContractApiTests(TestCase):
    """Test unauthenticated smart contract API access"""

    def setUp(self):
        self.client = APIClient()

    def test_auth_required(self):
        """
        Test that authentication is required
        for accessing smart contracts
        """
        res = self.client.get(SMART_CONTRACT_URL)
        self.assertEqual(res.status_code, status.HTTP_403_FORBIDDEN)


class PrivateSmartContractApiTests(TestCase):
    """Test authenticated smart contract API access"""

    def setUp(self):
        self.client = APIClient()

        # Patch Keycloak user creation within the setUp method
        patcher = patch('inethi.settings.KEYCLOAK_ADMIN.create_user')
        self.mock_keycloak_create_user = patcher.start()
        self.mock_keycloak_create_user.return_value = 'mock-keycloak-user-id'

        self.user = create_user(
            email='test@example.com',
            password='password123',
            username='test_username',
            first_name='Test First Name',
            last_name='Test Last Name',
        )
        self.client.force_authenticate(self.user)

        self.addCleanup(patcher.stop)

    def test_retrieve_smart_contracts(self):
        """Test retrieving a list of smart contracts"""
        create_smart_contract(user=self.user)
        create_smart_contract(
            user=self.user,
            address='0x1234567890ABCDEF',
            name='Another Contract'
        )

        res = self.client.get(SMART_CONTRACT_URL)

        smart_contracts = SmartContract.objects.all()
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(len(res.data), smart_contracts.count())

    def test_retrieve_smart_contract_detail(self):
        """Test retrieving a single smart contract"""
        smart_contract = create_smart_contract(user=self.user)

        url = detail_url(smart_contract.id)
        res = self.client.get(url)

        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data['id'], smart_contract.id)

    def test_create_smart_contract_not_allowed(
            self
    ):
        """
        Test that creating a smart contract is
        not allowed for non-admin users
        """
        payload = {
            'name': 'Unauthorized Contract',
            'address': '0xabcdef1234567890',
            'description': 'Should not be created',
            'write_access': True,
            'read_access': True,
            'contract_type': 'eth faucet',
        }
        res = self.client.post(SMART_CONTRACT_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_403_FORBIDDEN)

    def test_fail_not_admin_give_to(self):
        """Test that non-admin cannot call give to"""
        faucet_contract = FaucetSmartContract.objects.create(
            user=self.user,
            name='Test Faucet',
            address='0xfaucetaddress',
            description='Test Faucet Description',
            write_access=True,
            read_access=True,
            contract_type='eth faucet',
            give_to=True,
        )
        url = faucet_give_to_url(faucet_contract.id)
        payload = {'address': '0xgivetoaddress'}
        res = self.client.post(url, payload)
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)

    @patch('utils.crypto.CryptoUtils.account_index_check_active')
    def test_registry_check_active(
            self,
            mock_account_index_check_active
    ):
        """
        Test that the registry check method passes
        with registered user
        """
        mock_account_index_check_active.return_value = True

        account_index_contract = AccountsIndexContract.objects.create(
            user=self.user,
            name='Test Account Index',
            address='0xabcdefabcdefabcd',
            description='Test Account Index Description',
            write_access=True,
            read_access=True,
            contract_type='account index',
            add=True,
            is_active=True,
            owner_address=settings.ACCOUNT_INDEX_ADMIN_WALLET_ADDRESS,
        )

        private_key = encrypt_private_key('secret-key')
        user_wallet = Wallet.objects.create(
            user=self.user,
            name='Test Wallet',
            private_key=private_key,
            address='0xabcdefabcdefabcd',
        )

        url = registry_is_active_url(account_index_contract.id)
        payload = {
            'address': user_wallet.address,
        }

        rsp = self.client.post(url, payload)

        self.assertEqual(rsp.status_code, status.HTTP_200_OK)
        self.assertEqual(account_index_contract.is_active, True)

    def test_registry_fail_no_check_active(
            self,
    ):
        """
        Test that the registry check method fails
        when no check_active function is present
        """

        account_index_contract = AccountsIndexContract.objects.create(
            user=self.user,
            name='Test Account Index',
            address='0xabcdefabcdefabcd',
            description='Test Account Index Description',
            write_access=True,
            read_access=True,
            contract_type='account index',
            add=True,
            is_active=False,
            owner_address=settings.ACCOUNT_INDEX_ADMIN_WALLET_ADDRESS,
        )

        private_key = encrypt_private_key('secret-key')
        user_wallet = Wallet.objects.create(
            user=self.user,
            name='Test Wallet',
            private_key=private_key,
            address='0xabcdefabcdefabcd',
        )

        url = registry_is_active_url(account_index_contract.id)
        payload = {
            'address': user_wallet.address,
        }

        rsp = self.client.post(url, payload)

        self.assertEqual(rsp.status_code, status.HTTP_400_BAD_REQUEST)


class AdminSmartContractApiTests(TestCase):
    """Test admin-only smart contract API access"""

    def setUp(self):
        self.client = APIClient()

        patcher = patch('inethi.settings.KEYCLOAK_ADMIN.create_user')
        self.mock_keycloak_create_user = patcher.start()
        self.mock_keycloak_create_user.return_value = 'mock-keycloak-user-id'
        self.admin_user = create_user(
            email='admin@example.com',
            password='adminpass123',
            username='adminuser',
            is_staff=True,
            is_superuser=True,
        )

        self.client.force_authenticate(self.admin_user)

        self.addCleanup(patcher.stop)

    @patch('utils.crypto.CryptoUtils.registry_add')
    def test_registry_add_success(
            self,
            mock_registry_add
    ):
        """Test successful registry_add action for account index contract"""
        mock_tx_receipt = {
            'transactionHash': '0x123abc',
            'blockHash': '0x456def',
            'blockNumber': 12345,
            'gasUsed': 21000,
            'status': 1,
            'transactionIndex': 0,
        }

        mock_registry_add.return_value = mock_tx_receipt

        # Create an account index smart contract with 'add' function enabled
        account_index_contract = AccountsIndexContract.objects.create(
            user=self.admin_user,
            name='Test Account Index',
            address='0xabcdefabcdefabcd',
            description='Test Account Index Description',
            write_access=True,
            read_access=True,
            contract_type='account index',
            add=True,  # Enable 'add' function
            owner_address=settings.ACCOUNT_INDEX_ADMIN_WALLET_ADDRESS,
        )

        test_user = create_user(
            email='user@example.com',
            password='password123',
            username='user_username',
            first_name='user First Name',
            last_name='user Last Name',
        )

        # Create a wallet for the user
        wallet = Wallet.objects.create(
            user=test_user,
            name='Test Wallet',
            private_key='encrypted_private_key',
            address='0xuserwalletaddress',
        )

        p_key_admin = encrypt_private_key('admin_encrypted_private_key')
        Wallet.objects.create(
            user=self.admin_user,
            name='Admin Wallet',
            private_key=p_key_admin,
            address=settings.ACCOUNT_INDEX_ADMIN_WALLET_ADDRESS,
        )

        url = registry_add_url(account_index_contract.id)
        payload = {'address': wallet.address}

        res = self.client.post(url, payload)
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertIn('transaction_receipt', res.data)
        self.assertEqual(res.data['transaction_receipt'], mock_tx_receipt)

    def test_registry_add_no_wallet(self):
        """
        Test registry_add fails when user
        does not have the wallet address
        """
        # Create an account index smart contract
        account_index_contract = AccountsIndexContract.objects.create(
            user=self.admin_user,
            name='Test Account Index',
            address='0xabcdefabcdefabcd',
            description='Test Account Index Description',
            write_access=True,
            read_access=True,
            contract_type='account index',
            add=True,
            owner_address=settings.ACCOUNT_INDEX_ADMIN_WALLET_ADDRESS,
        )

        url = registry_add_url(account_index_contract.id)
        payload = {'address': '0xnonexistentwalletaddress'}
        res = self.client.post(url, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', res.data)

    def test_registry_add_invalid_contract_type(self):
        """Test registry_add fails when contract type is not 'account index'"""
        # Create a faucet smart contract
        faucet_contract = FaucetSmartContract.objects.create(
            user=self.admin_user,
            name='Test Faucet',
            address='0xfaucetaddress',
            description='Test Faucet Description',
            write_access=True,
            read_access=True,
            contract_type='eth faucet',
            gimme=True,
        )

        user = create_user(
            email='user@example.com',
            password='password123',
            username='user_username',
            first_name='user First Name',
            last_name='user Last Name',
        )

        # Create a wallet for the user
        wallet = Wallet.objects.create(
            user=user,
            name='Test Wallet',
            private_key='encrypted_private_key',
            address='0xuserwalletaddress',
        )

        url = registry_add_url(faucet_contract.id)
        payload = {'address': wallet.address}
        res = self.client.post(url, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('contract_type', res.data)

    def test_registry_add_no_add_function(self):
        """Test registry_add fails when 'add' function is not enabled"""
        # Create an account index smart contract with 'add' function disabled
        account_index_contract = AccountsIndexContract.objects.create(
            user=self.admin_user,
            name='Test Account Index',
            address='0xabcdefabcdefabcd',
            description='Test Account Index Description',
            write_access=True,
            read_access=True,
            contract_type='account index',
            add=False,  # 'add' function disabled
            owner_address=settings.ACCOUNT_INDEX_ADMIN_WALLET_ADDRESS,
        )

        user = create_user(
            email='user@example.com',
            password='password123',
            username='user_username',
            first_name='user First Name',
            last_name='user Last Name',
        )

        # Create a wallet for the user
        wallet = Wallet.objects.create(
            user=user,
            name='Test Wallet',
            private_key='encrypted_private_key',
            address='0xuserwalletaddress',
        )

        url = registry_add_url(account_index_contract.id)
        payload = {'address': wallet.address}
        res = self.client.post(url, payload)

        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', res.data)

    def test_create_smart_contract(self):
        """Test creating a smart contract as admin"""
        payload = {
            'name': 'Admin Contract',
            'owner_address': settings.FAUCET_ADMIN_WALLET_ADDRESS,
            'address': '0xadmincontractaddress',
            'description': 'Created by admin',
            'write_access': True,
            'read_access': True,
            'contract_type': 'eth faucet',
            'gimme': True,  # For FaucetSmartContract
        }
        res = self.client.post(SMART_CONTRACT_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_201_CREATED)

        smart_contract = SmartContract.objects.get(id=res.data['id'])
        self.assertEqual(smart_contract.name, payload['name'])
        self.assertEqual(smart_contract.user, self.admin_user)

    def test_update_smart_contract(self):
        """Test updating a smart contract as admin"""
        smart_contract = create_smart_contract(user=self.admin_user)
        payload = {'name': 'Updated Contract Name'}

        url = detail_url(smart_contract.id)
        res = self.client.patch(url, payload)
        self.assertEqual(res.status_code, status.HTTP_200_OK)

        smart_contract.refresh_from_db()
        self.assertEqual(smart_contract.name, payload['name'])

    def test_delete_smart_contract(self):
        """Test deleting a smart contract as admin"""
        smart_contract = create_smart_contract(user=self.admin_user)

        url = detail_url(smart_contract.id)
        res = self.client.delete(url)
        self.assertEqual(res.status_code, status.HTTP_204_NO_CONTENT)

        exists = SmartContract.objects.filter(id=smart_contract.id).exists()
        self.assertFalse(exists)

    @patch('utils.crypto.CryptoUtils.faucet_give_to')
    def test_faucet_give_to(
            self,
            mock_faucet_give_to
    ):
        """
        Test successful faucet give to action
        for account in the account index
        """
        mock_tx_receipt = {
            'transactionHash': '0x123abc',
            'blockHash': '0x456def',
            'blockNumber': 12345,
            'gasUsed': 21000,
            'status': 1,
            'transactionIndex': 0,
        }

        mock_faucet_give_to.return_value = mock_tx_receipt

        # Create a faucet smart contract with 'give_to' function enabled
        faucet_contract = FaucetSmartContract.objects.create(
            user=self.admin_user,
            name='Test Faucet',
            address='0xABCDEFabcdefabcd',
            description='Test Faucet Description',
            write_access=True,
            read_access=True,
            contract_type='eth faucet',
            give_to=True,
            owner_address=settings.FAUCET_ADMIN_WALLET_ADDRESS,
        )

        test_user = create_user(
            email='test@example.com',
            password='password123',
            username='test_username',
            first_name='Test First Name',
            last_name='Test Last Name',
        )

        wallet = Wallet.objects.create(
            user=test_user,
            name='Test Wallet',
            private_key='encrypted_private_key',
            address='0xuserwalletaddress',
        )

        p_key_admin = encrypt_private_key(self.admin_user.password)
        Wallet.objects.create(
            user=self.admin_user,
            name='Admin Wallet',
            private_key=p_key_admin,
            address=settings.ACCOUNT_INDEX_ADMIN_WALLET_ADDRESS,
        )
        url = faucet_give_to_url(faucet_contract.id)
        payload = {'address': wallet.address}

        res = self.client.post(url, payload)
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertIn('transaction_receipt', res.data)
        self.assertEqual(res.data['transaction_receipt'], mock_tx_receipt)

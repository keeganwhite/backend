from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework import status
from django.test import TestCase
from unittest.mock import patch
# from unittest.mock import MagicMock
from core.models import Wallet
from django.urls import reverse

from utils.crypto import decrypt_private_key, encrypt_private_key

CREATE_WALLET_URL = reverse('wallet:wallet-list')
HAS_WALLET_URL = reverse('wallet:wallet-has-wallet')


def detail_url(wallet_pk):
    """Create and return a wallet detail URL."""
    return reverse('wallet:wallet-detail', args=[wallet_pk])


def send_token_url(wallet_pk):
    """Create and return a wallet send token URL."""
    return reverse('wallet:wallet-send-token', args=[wallet_pk])


def create_user(**params):
    """Helper function to create a user"""
    return get_user_model().objects.create_user(**params)


def create_wallet(**params):
    """Helper function to create a wallet"""
    return Wallet.objects.create(**params)


class PublicWalletApiTests(TestCase):
    """Test the publicly available wallet API"""

    def setUp(self):
        self.client = APIClient()

    def test_auth_required_creating_wallet(self):
        """Test that authentication is required for creating a wallet"""
        res = self.client.post(CREATE_WALLET_URL, {})

        self.assertEqual(res.status_code, status.HTTP_403_FORBIDDEN)

    def test_auth_required_checking_wallet(self):
        """Test that authentication is required for checking a wallet"""
        res = self.client.post(HAS_WALLET_URL, {})

        self.assertEqual(res.status_code, status.HTTP_403_FORBIDDEN)

    def test_auth_required_updating_wallet(self):
        """Test that authentication is required for updating a wallet"""
        wallet_id = 1
        payload = {
            'name': 'Updated Wallet Name',
        }
        url = detail_url(wallet_id)
        res = self.client.patch(url, payload)
        self.assertEqual(res.status_code, status.HTTP_403_FORBIDDEN)

    def test_auth_required_send_token(self):
        """Test that authentication is required for sending a token"""
        url = send_token_url(1)
        res = self.client.post(
            url,
            {
                'recipient_address': '0x1',
                'amount': 1
            }
        )
        self.assertEqual(res.status_code, status.HTTP_403_FORBIDDEN)

    def test_auth_required_deleting_wallet(self):
        """Test that authentication is required for deleting a wallet"""
        wallet_id = 1
        url = detail_url(wallet_id)
        res = self.client.delete(url)
        self.assertEqual(res.status_code, status.HTTP_403_FORBIDDEN)


class PrivateWalletApiTests(TestCase):
    """Test the private wallet API"""

    def setUp(self):
        patcher = patch('inethi.settings.KEYCLOAK_ADMIN.create_user')
        self.mock_keycloak_create_user = patcher.start()
        self.mock_keycloak_create_user.return_value = 'mock-keycloak-user-id'

        # Set up user and authenticated client
        self.user = create_user(
            email='test@example.com',
            password='testpass123',
            username='test_username',
            first_name='Test First Name',
            last_name='Test Last Name',
        )
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

        # Stop the patch when tests finish
        self.addCleanup(patcher.stop)

    def test_delete_wallet_success(self):
        """Test that a wallet can be deleted if you own it"""
        wallet = Wallet.objects.create(
            user=self.user,
            name='Test Wallet',
            private_key='test-encrypted-key',
            address='test-wallet-address'
        )
        url = detail_url(wallet.pk)

        res = self.client.delete(url)

        self.assertEqual(res.status_code, status.HTTP_204_NO_CONTENT)

        wallet_exists = Wallet.objects.filter(pk=wallet.pk).exists()
        self.assertFalse(wallet_exists)

    def test_delete_wallet_fail(self):
        """Test that a wallet cannot be deleted if you do not own it"""
        client_two = create_user(
            email='test_two@example.com',
            password='testpass123',
            username='test_username_2',
            first_name='Test First Name',
            last_name='Test Last Name',
        )

        wallet_two = Wallet.objects.create(
            user=client_two,
            name='Test Wallet Two',
            private_key='test-two-encrypted-key',
            address='test-two-wallet-address'
        )
        url = detail_url(wallet_two.pk)
        res = self.client.delete(url)
        self.assertEqual(res.status_code, status.HTTP_404_NOT_FOUND)

    @patch('utils.crypto.CryptoUtils.faucet_give_to')
    @patch('utils.crypto.CryptoUtils.registry_add')
    @patch('utils.crypto.CryptoUtils.create_wallet')
    def test_create_wallet_success(
            self,
            mock_create_wallet,
            mock_registry_add,
            mock_faucet_give_to
    ):
        """
        Test that a wallet can be created and
        details can be received. The wallet
        should also be added to the Krone
        account index
        """

        mock_tx_receipt = {
            'transactionHash': '0x123abc',
            'blockHash': '0x456def',
            'blockNumber': 12345,
            'gasUsed': 21000,
            'status': 1,
            'transactionIndex': 0,
        }
        mock_registry_add.return_value = mock_tx_receipt
        mock_faucet_give_to.return_value = mock_tx_receipt

        # Mock the response of CryptoUtils.create_wallet()
        mock_create_wallet.return_value = {
            'private_key': 'mock-private-key',
            'address': 'mock-wallet-address'
        }

        # Create admin wallet and user
        admin_user = create_user(
            email='admin@example.com',
            password='password123',
            username='admin_username',
            first_name='Admin First Name',
            last_name='Admin Last Name',
        )
        p_key_admin = encrypt_private_key('admin_encrypted_private_key')
        Wallet.objects.create(
            user=admin_user,
            name='Admin Wallet',
            private_key=p_key_admin,
            address=settings.ACCOUNT_INDEX_ADMIN_WALLET_ADDRESS,
        )

        payload = {
            'name': 'Test Wallet',
        }

        # Send the request to create the wallet
        res = self.client.post(CREATE_WALLET_URL, payload)

        # Ensure the wallet creation is successful
        self.assertEqual(res.status_code, status.HTTP_201_CREATED)

        # Check if the wallet exists for the authenticated user
        wallet_exists = Wallet.objects.filter(user=self.user).exists()
        self.assertTrue(wallet_exists)

        # Verify the wallet data
        created_wallet = Wallet.objects.get(user=self.user)
        self.assertEqual(created_wallet.name, payload['name'])
        self.assertEqual(created_wallet.address, 'mock-wallet-address')
        decrypted_key = decrypt_private_key(created_wallet.private_key)
        self.assertEqual(decrypted_key, 'mock-private-key')

    def test_update_wallet_name_success(self):
        """
        Test that a wallet's name can
        be updated successfully by its owner
        """
        wallet = Wallet.objects.create(
            user=self.user,
            name='Original Wallet Name',
            private_key='test-encrypted-key',
            address='test-wallet-address'
        )
        url = detail_url(wallet.pk)
        payload = {'name': 'Updated Wallet Name'}

        res = self.client.patch(url, payload)

        self.assertEqual(res.status_code, status.HTTP_200_OK)
        wallet.refresh_from_db()
        self.assertEqual(wallet.name, payload['name'])

    def test_update_wallet_name_not_owner(self):
        """Test that a user cannot update another user's wallet name"""
        client_two = create_user(
            email='test_two@example.com',
            password='testpass123',
            username='test_username_2',
            first_name='Test First Name',
            last_name='Test Last Name',
        )
        wallet_two = Wallet.objects.create(
            user=client_two,
            name='Test Wallet Two',
            private_key='test-two-encrypted-key',
            address='test-two-wallet-address'
        )
        url = detail_url(wallet_two.pk)
        payload = {'name': 'New Name'}

        res = self.client.patch(url, payload)
        self.assertEqual(res.status_code, status.HTTP_404_NOT_FOUND)

    def test_has_wallet(self):
        """Test checking if the authenticated user has a wallet"""
        Wallet.objects.create(
            user=self.user,
            name='Test Wallet',
            private_key='test-encrypted-key',
            address='test-wallet-address'
        )
        res = self.client.get(HAS_WALLET_URL)
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertTrue(res.data['has_wallet'])

    # @patch('utils.crypto.CryptoUtils.send_to_wallet_address')
    # def test_send_tokens_success(self, mock_send_token):
    #     """Test that tokens can be sent successfully to another wallet"""
    #     # Create a wallet for the authenticated user
    #     wallet = Wallet.objects.create(
    #         user=self.user,
    #         name='Test Wallet',
    #         private_key='test-encrypted-key',
    #         address='test-wallet-address'
    #     )
    #     url = send_token_url(wallet.pk)  # Pass the correct wallet pk
    #     payload = {
    #         'recipient_address': 'recipient-wallet-address',
    #         'amount': 50
    #     }
    #
    #     # Mock transaction receipt
    #     mock_tx_receipt = MagicMock()
    #     mock_tx_receipt.transactionHash.hex.return_value = '0x123abc'
    #     mock_tx_receipt.blockHash.hex.return_value = '0x456def'
    #     mock_tx_receipt.blockNumber = 12345
    #     mock_tx_receipt.gasUsed = 21000
    #     mock_tx_receipt.status = 1
    #     mock_tx_receipt.transactionIndex = 0
    #
    #     # Set the mock return value
    #     mock_send_token.return_value = mock_tx_receipt
    #
    #     # Send the request to the API
    #     res = self.client.post(url, payload)
    #
    #     # Debug response in case of failure
    #     if res.status_code != status.HTTP_200_OK:
    #         print("Response data:", res.data)
    #
    #     # Assert response status and content
    #     self.assertEqual(res.status_code, status.HTTP_200_OK)
    #     self.assertIn('transaction_receipt', res.data)

    def test_send_tokens_missing_recipient(self):
        """
        Test that sending tokens fails when the
        recipient address is missing
        """
        encrypted_key = encrypt_private_key('mock-private-key')
        wallet = Wallet.objects.create(
            user=self.user,
            name='Test Wallet',
            private_key=encrypted_key,
            address='test-wallet-address'
        )
        url = send_token_url(wallet.pk)
        payload = {'amount': 50}

        res = self.client.post(url, payload)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', res.data)

    def test_send_tokens_not_owner(self):
        """Test that a user cannot send tokens from another user's wallet"""
        client_two = create_user(
            email='test_two@example.com',
            password='testpass123',
            username='test_username_2',
            first_name='Test First Name',
            last_name='Test Last Name',
        )
        encrypted_key = encrypt_private_key('mock-private-key')
        wallet_two = Wallet.objects.create(
            user=client_two,
            name='Test Wallet Two',
            private_key=encrypted_key,
            address='test-two-wallet-address'
        )
        url = send_token_url(wallet_two.pk)
        payload = {
            'recipient_address': 'recipient-wallet-address',
            'amount': 50
        }

        res = self.client.post(url, payload)
        self.assertEqual(res.status_code, status.HTTP_404_NOT_FOUND)

    def test_retrieve_own_wallet_details(self):
        """
        Test that the authenticated user can
        retrieve their own wallet details
        """
        encrypted_key = encrypt_private_key('mock-private-key')
        wallet = Wallet.objects.create(
            user=self.user,
            name='Test Wallet',
            private_key=encrypted_key,
            address='test-wallet-address'
        )
        url = detail_url(wallet.pk)

        res = self.client.get(url)
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data['name'], wallet.name)

    def test_retrieve_other_user_wallet_details(self):
        """Test that accessing another user's wallet details returns a 404"""
        encrypted_key = encrypt_private_key('mock-private-key')
        client_two = create_user(
            email='test_two@example.com',
            password='testpass123',
            username='test_username_2',
            first_name='Test First Name',
            last_name='Test Last Name',
        )

        wallet_two = Wallet.objects.create(
            user=client_two,
            name='Test Wallet Two',
            private_key=encrypted_key,
            address='test-two-wallet-address'
        )
        url = detail_url(wallet_two.pk)

        res = self.client.get(url)
        self.assertEqual(res.status_code, status.HTTP_404_NOT_FOUND)

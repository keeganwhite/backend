from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework import status

from core.models import (
    Transaction
)

# Standard list view
TRANSACTION_LIST_URL = reverse(
    'transaction:transaction-list'
)  # Output: /api/v1/transactions/

# Custom action
TRANSACTION_BY_USER_URL = reverse(
    'transaction:transaction-list-by-user'
)  # Output: /api/v1/transactions/by-user/


def detail_url(transaction_id):
    """Return smart contract detail URL"""
    return reverse(
        'transaction:transaction-detail',
        args=[transaction_id]
    )


def create_user(**params):
    """Helper function to create a user"""
    return get_user_model().objects.create_user(**params)


class PublicSmartContractApiTests(TestCase):
    """Test unauthenticated smart contract API access"""

    def setUp(self):
        self.client = APIClient()

    def test_auth_required(self):
        """
        Test that authentication is required
        for accessing smart contracts
        """
        res = self.client.get(TRANSACTION_LIST_URL)
        self.assertEqual(res.status_code, status.HTTP_403_FORBIDDEN)
        res = self.client.get(TRANSACTION_BY_USER_URL)
        self.assertEqual(res.status_code, status.HTTP_403_FORBIDDEN)


class PrivateAPITests(TestCase):
    """Test the private API"""
    def setUp(self):
        self.client = APIClient()

        patcher = patch('inethi.settings.KEYCLOAK_ADMIN.create_user')
        self.mock_keycloak_create_user = patcher.start()
        self.mock_keycloak_create_user.return_value = 'mock-keycloak-user-id'
        self.user = create_user(
            email='test@example.com',
            password='testpass123',
            username='testuser',
        )
        self.client.force_authenticate(self.user)
        self.addCleanup(patcher.stop)

    def test_list_transactions(self):
        """Test listing transactions for a user"""
        other_user_1 = create_user(
            email='other_1@example.com',
            password='password123',
            username='other_1_username',
            first_name='other_1 First Name',
            last_name='other_1 Last Name',
        )

        other_user_2 = create_user(
            email='other_2@example.com',
            password='password123',
            username='other_2_username',
            first_name='other_2 First Name',
            last_name='other_2 Last Name',
        )

        transaction_user = Transaction.objects.create(
            sender=self.user,
            recipient=other_user_1,

            recipient_address='mock address',
            amount='10.1',
            transaction_hash='mock hash',
            block_number=123,
            gas_used='10.2',
            category='Transfer'
        )
        Transaction.objects.create(
            sender=other_user_2,
            recipient=other_user_1,

            recipient_address='mock address 2',
            amount='10.1',
            transaction_hash='mock hash 2',
            block_number=123,
            gas_used='10.2',
            category='Transfer'
        )
        url = TRANSACTION_BY_USER_URL
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            len(response.data),
            1
        )  # Only one transaction should be visible

        # Assert that other_user_2 is not in the returned data
        for transaction in response.data:
            self.assertNotEqual(transaction['sender'], other_user_2.id)
            self.assertNotEqual(transaction['recipient'], other_user_2.id)

        # Assert that the returned transaction matches the expected one
        self.assertEqual(response.data[0]['id'], transaction_user.id)
        self.assertEqual(
            response.data[0]['recipient_address'],
            transaction_user.recipient_address
        )

    def test_list_transactions_empty(self):
        """
        Test that no transactions are returned for
        a user with no transactions
        """
        url = TRANSACTION_LIST_URL
        other_user_1 = create_user(
            email='other_1@example.com',
            password='password123',
            username='other_1_username',
            first_name='other_1 First Name',
            last_name='other_1 Last Name',
        )

        other_user_2 = create_user(
            email='other_2@example.com',
            password='password123',
            username='other_2_username',
            first_name='other_2 First Name',
            last_name='other_2 Last Name',
        )

        Transaction.objects.create(
            sender=other_user_2,
            recipient=other_user_1,

            recipient_address='mock address 2',
            amount='10.1',
            transaction_hash='mock hash 2',
            block_number=123,
            gas_used='10.2',
            category='Transfer'
        )

        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 0)

    def test_list_transactions_multiple(self):
        """Test listing multiple transactions involving a user"""
        other_user = create_user(
            email='other@example.com',
            password='password123',
            username='other_username',
        )

        transaction_1 = Transaction.objects.create(
            sender=self.user,
            recipient=other_user,
            recipient_address='mock address 1',
            amount='5.0',
            transaction_hash='mock hash 1',
            block_number=101,
            gas_used='1.0',
            category='Transfer'
        )
        transaction_2 = Transaction.objects.create(
            sender=other_user,
            recipient=self.user,
            recipient_address='mock address 2',
            amount='7.0',
            transaction_hash='mock hash 2',
            block_number=102,
            gas_used='2.0',
            category='Transfer'
        )

        url = TRANSACTION_BY_USER_URL
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)

        transaction_ids = [t['id'] for t in response.data]
        self.assertIn(transaction_1.id, transaction_ids)
        self.assertIn(transaction_2.id, transaction_ids)

    def test_transaction_detail_unauthorized(self):
        """Test that unauthorized access to a transaction is forbidden"""
        other_user = create_user(
            email='other@example.com',
            password='password123',
            username='other_username',
        )

        transaction = Transaction.objects.create(
            sender=other_user,
            recipient=other_user,
            recipient_address='mock address',
            amount='10.0',
            transaction_hash='mock hash',
            block_number=101,
            gas_used='1.0',
            category='Transfer'
        )

        url = reverse('transaction:transaction-detail', args=[transaction.id])
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class AdminTransactionAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()

        patcher = patch('inethi.settings.KEYCLOAK_ADMIN.create_user')
        self.mock_keycloak_create_user = patcher.start()
        self.mock_keycloak_create_user.return_value = 'mock-keycloak-user-id'
        self.user = create_user(
            email='test@example.com',
            password='testpass123',
            username='testuser',
            is_staff=True,
            is_superuser=True,
        )
        self.client.force_authenticate(self.user)
        self.addCleanup(patcher.stop)

    def test_list_transactions(self):
        """Test listing transactions for admin user returns all transactions"""
        other_user_1 = create_user(
            email='other_1@example.com',
            password='password123',
            username='other_1_username',
            first_name='other_1 First Name',
            last_name='other_1 Last Name',
        )

        other_user_2 = create_user(
            email='other_2@example.com',
            password='password123',
            username='other_2_username',
            first_name='other_2 First Name',
            last_name='other_2 Last Name',
        )

        Transaction.objects.create(
            sender=self.user,
            recipient=other_user_1,

            recipient_address='mock address',
            amount='10.1',
            transaction_hash='mock hash',
            block_number=123,
            gas_used='10.2',
            category='Transfer'
        )
        Transaction.objects.create(
            sender=other_user_2,
            recipient=other_user_1,

            recipient_address='mock address 2',
            amount='10.1',
            transaction_hash='mock hash 2',
            block_number=123,
            gas_used='10.2',
            category='Transfer'
        )
        url = TRANSACTION_BY_USER_URL
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)

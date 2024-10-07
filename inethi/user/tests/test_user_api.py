from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework import status

CREATE_USER_URL = reverse('user:create')
TOKEN_URL = reverse('user:token')
ME_URL = reverse('user:me')


def create_user(**params):
    """Helper function to create a user"""
    return get_user_model().objects.create_user(**params)


class PublicUserApiTests(TestCase):
    """Test public user API endpoints"""

    def setUp(self):
        self.client = APIClient()

    @patch('inethi.settings.KEYCLOAK_ADMIN.create_user')
    def test_create_valid_user_success(self, mock_keycloak_create_user):
        """Test creating user with valid payload is successful"""
        mock_keycloak_create_user.return_value = 'mock-keycloak-user-id'
        payload = {
            'email': 'test@example.com',
            'password': 'testpassword123',
            'name': 'Test name'
        }

        res = self.client.post(CREATE_USER_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        user = get_user_model().objects.get(email=payload['email'])
        self.assertTrue(user.check_password(payload['password']))
        self.assertNotIn('password', res.data)
        mock_keycloak_create_user.assert_called_once()

    @patch('inethi.settings.KEYCLOAK_ADMIN.create_user')
    def test_create_user_with_email_exists_error(
            self,
            mock_keycloak_create_user
    ):
        """
        Test error returned when creating user with email that already exists
        """
        mock_keycloak_create_user.return_value = 'mock-keycloak-user-id'
        payload = {
            'email': 'test@example.com',
            'password': 'testpassword123',
            'name': 'Test name'
        }
        create_user(**payload)
        res = self.client.post(CREATE_USER_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    @patch('inethi.settings.KEYCLOAK_ADMIN.create_user')
    def test_password_too_short_error(self, mock_keycloak_create_user):
        """Test that password must be more than 5 characters"""
        payload = {
            'email': 'test@example.com',
            'password': 'test',
            'name': 'Test name'
        }
        res = self.client.post(CREATE_USER_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        user_exists = get_user_model().objects.filter(
            email=payload['email']
        ).exists()
        self.assertFalse(user_exists)

    @patch('inethi.settings.KEYCLOAK_OPENID.userinfo')
    @patch('inethi.settings.KEYCLOAK_OPENID.introspect')
    @patch('inethi.settings.KEYCLOAK_OPENID.token')
    @patch('inethi.settings.KEYCLOAK_ADMIN.create_user')
    def test_create_token_for_user(
            self,
            mock_keycloak_create_user,
            mock_keycloak_token,
            mock_keycloak_introspect,
            mock_keycloak_userinfo
    ):
        """Test that a token is created for the user with valid credentials"""
        mock_keycloak_create_user.return_value = 'mock-keycloak-user-id'
        mock_keycloak_token.return_value = {
            'access_token': 'mock-token',
            'token_type': 'Bearer'
        }
        mock_keycloak_userinfo.return_value = {'email': 'test@example.com'}

        # Mock introspect to return a valid response
        mock_keycloak_introspect.return_value = {'active': True}

        user_details = {
            'email': 'test@example.com',
            'password': 'testpassword123',
            'name': 'Test name'
        }
        create_user(**user_details)

        payload = {
            'email': user_details['email'],
            'password': user_details['password'],
        }
        res = self.client.post(TOKEN_URL, payload)

        # Ensure 'token' is present in response
        self.assertIn('token', res.data)
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        mock_keycloak_token.assert_called_once()
        mock_keycloak_introspect.assert_called_once()

    @patch('inethi.settings.KEYCLOAK_ADMIN.create_user')
    @patch('inethi.settings.KEYCLOAK_OPENID.token')
    def test_create_token_invalid_credentials(
            self,
            mock_keycloak_token,
            mock_keycloak_create_user
    ):
        """Test that token is not created if invalid credentials are given"""
        mock_keycloak_create_user.return_value = 'mock-keycloak-user-id'
        mock_keycloak_token.side_effect = Exception("Invalid credentials")

        user_details = {
            'email': 'test@example.com',
            'password': 'testpassword123',
            'name': 'Test name'
        }
        create_user(**user_details)

        payload = {
            'email': user_details['email'],
            'password': 'badpassword',
        }
        res = self.client.post(TOKEN_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    @patch('inethi.settings.KEYCLOAK_ADMIN.create_user')
    def test_create_token_no_password(self, mock_keycloak_create_user):
        """Test that token is not created if no password is given"""
        payload = {
            'email': 'test@example.com',
            'password': '',
            'name': 'Test name'
        }
        res = self.client.post(TOKEN_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_retrieve_user_unauthorized(self):
        """Test that authentication is required for users"""
        res = self.client.get(ME_URL)
        self.assertEqual(
            res.status_code,
            status.HTTP_403_FORBIDDEN
        )  # seems to be 403 without token


class PrivateUserApiTests(TestCase):
    """Test API requests that require authentication"""

    def setUp(self):
        # Patch Keycloak user creation
        patcher = patch('inethi.settings.KEYCLOAK_ADMIN.create_user')
        self.mock_keycloak_create_user = patcher.start()
        self.mock_keycloak_create_user.return_value = 'mock-keycloak-user-id'

        # Set up user and authenticated client
        self.user = create_user(
            email='test@example.com',
            password='testpass123',
            name='Test Name'
        )
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

        # Stop the patch when tests finish
        self.addCleanup(patcher.stop)

    def test_retrieve_profile_success(self):
        """Test retrieving profile for logged in user"""
        res = self.client.get(ME_URL)

        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data, {
            'name': self.user.name,
            'email': self.user.email
        })

    def test_post_me_not_allowed(self):
        """Test that POST is not allowed for this endpoint"""
        res = self.client.post(ME_URL, {})
        self.assertEqual(res.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    def test_update_user_profile(self):
        """Test updating user profile for authenticated user"""
        payload = {"name": "Updated Name", "password": "newpassword123"}

        res = self.client.patch(ME_URL, payload)

        self.user.refresh_from_db()
        self.assertEqual(self.user.name, payload['name'])
        self.assertTrue(self.user.check_password(payload['password']))
        self.assertEqual(res.status_code, status.HTTP_200_OK)

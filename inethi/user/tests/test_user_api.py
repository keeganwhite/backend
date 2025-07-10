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
    def test_create_user_no_email(self, mock_keycloak_create_user):
        """Test creating user without providing an email generates one"""
        mock_keycloak_create_user.return_value = 'mock-keycloak-user-id'
        payload = {
            'password': 'testpassword123',
            'first_name': 'test first name',
            'last_name': 'test last name',
            'username': 'test_username'
        }

        res = self.client.post(CREATE_USER_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        user = get_user_model().objects.get(username=payload['username'])
        expected_email = f"{payload['username']}@inethi.com"
        self.assertEqual(user.email, expected_email)
        self.assertTrue(user.check_password(payload['password']))
        self.assertNotIn('password', res.data)
        mock_keycloak_create_user.assert_called_once()

    @patch('inethi.settings.KEYCLOAK_ADMIN.create_user')
    def test_create_user_no_phone_number(self, mock_keycloak_create_user):
        """Test creating user without providing a phone number"""
        mock_keycloak_create_user.return_value = 'mock-keycloak-user-id'
        payload = {
            'email': 'test@example.com',
            'password': 'testpassword123',
            'first_name': 'test first name',
            'last_name': 'test last name',
            'username': 'test_username'
        }

        res = self.client.post(CREATE_USER_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        user = get_user_model().objects.get(email=payload['email'])
        self.assertIsNone(user.phone_number)
        self.assertTrue(user.check_password(payload['password']))
        self.assertNotIn('password', res.data)
        mock_keycloak_create_user.assert_called_once()

    @patch('inethi.settings.KEYCLOAK_ADMIN.create_user')
    def test_create_user_email_and_phone_missing(
            self,
            mock_keycloak_create_user
    ):
        """Test creating user without email and phone number"""
        mock_keycloak_create_user.return_value = 'mock-keycloak-user-id'
        payload = {
            'password': 'testpassword123',
            'first_name': 'test first name',
            'last_name': 'test last name',
            'username': 'test_username'
        }

        res = self.client.post(CREATE_USER_URL, payload)
        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        user = get_user_model().objects.get(username=payload['username'])
        expected_email = f"{payload['username']}@inethi.com"
        self.assertEqual(user.email, expected_email)
        self.assertIsNone(user.phone_number)  # Ensure phone is None
        self.assertTrue(user.check_password(payload['password']))
        mock_keycloak_create_user.assert_called_once()

    @patch('inethi.settings.KEYCLOAK_ADMIN.create_user')
    def test_create_valid_user_success(self, mock_keycloak_create_user):
        """Test creating user with valid payload is successful"""
        mock_keycloak_create_user.return_value = 'mock-keycloak-user-id'
        payload = {
            'email': 'test@example.com',
            'password': 'testpassword123',
            'first_name': 'test first name',
            'last_name': 'test last name',
            'username': 'test_username'
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
            'first_name': 'test first name',
            'last_name': 'test last name',
            'username': 'test_username'
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
            'first_name': 'test first name',
            'last_name': 'test last name',
            'username': 'test_username'
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
            'first_name': 'test first name',
            'last_name': 'test last name',
            'username': 'test_username'
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
            'first_name': 'test first name',
            'last_name': 'test last name',
            'username': 'test_username'
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
            'first_name': 'test first name',
            'last_name': 'test last name',
            'username': 'test_username'
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
            username='test_username',
            first_name='Test First Name',
            last_name='Test Last Name',
        )
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

        # Stop the patch when tests finish
        self.addCleanup(patcher.stop)

    def test_retrieve_profile_success(self):
        """Test retrieving profile for logged in user"""
        res = self.client.get(ME_URL)

        self.assertEqual(res.status_code, status.HTTP_200_OK)
        expected = {
            'id': self.user.id,
            'username': self.user.username,
            'email': self.user.email,
            'first_name': self.user.first_name,
            'last_name': self.user.last_name,
            'phone_number': self.user.phone_number  # likely None
        }
        self.assertEqual(res.data, expected)

    def test_post_me_not_allowed(self):
        """Test that POST is not allowed for this endpoint"""
        res = self.client.post(ME_URL, {})
        self.assertEqual(res.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)

    @patch('inethi.settings.KEYCLOAK_ADMIN.get_user_id')
    @patch('inethi.settings.KEYCLOAK_ADMIN.update_user')
    def test_update_user_profile(
            self,
            mock_keycloak_update_user,
            mock_get_user_id
    ):
        """Test updating user profile for authenticated user"""
        mock_get_user_id.return_value = 'mock-keycloak-user-id'
        mock_keycloak_update_user.return_value = {'status': 201}

        payload = {
            "email": self.user.email,
            "username": self.user.username,
            "first_name": "Updated First Name",
            "password": "newpassword123"
        }

        res = self.client.patch(ME_URL, payload)

        self.assertEqual(res.status_code, status.HTTP_200_OK)

        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, payload['first_name'])
        self.assertTrue(self.user.check_password(payload['password']))

        # Verify that the Keycloak update methods were called
        mock_get_user_id.assert_called_once_with(self.user.username)
        mock_keycloak_update_user.assert_called_once_with(
            'mock-keycloak-user-id',
            {
                "firstName": payload["first_name"],
                "lastName": self.user.last_name,
                "email": self.user.email,
                "username": self.user.username,
                "enabled": self.user.is_active,
            }
        )

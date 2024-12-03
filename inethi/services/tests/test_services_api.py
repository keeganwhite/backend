from unittest.mock import patch
from django.urls import reverse
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework import status
from core.models import (
    Service
)
from django.contrib.auth import get_user_model

SERVICES_URL_LIST = reverse('services:services-list')


def detail_url(service_id):
    """Return service detail URL"""
    return reverse(
        'services:services-detail',
        args=[service_id]
    )


def create_user(**params):
    """Helper function to create a user"""
    return get_user_model().objects.create_user(**params)


def create_service(**params):
    """Helper function to create a service"""
    defaults = {
        'name': 'Test Service',
        'description': 'Test Service',
        'type': 'utility',
        'paid': False
    }
    defaults.update(params)
    return Service.objects.create(**defaults)


class PublicServicesAPITests(TestCase):
    """Test unauthenticated services API"""

    def setUp(self):
        self.client = APIClient()

    def test_auth_required(self):
        """
        Test that authentication is required
        for accessing services API
        """
        res = self.client.get(SERVICES_URL_LIST)
        self.assertEqual(res.status_code, status.HTTP_403_FORBIDDEN)


class PrivateServiceContractApiTests(TestCase):
    """Test authenticated services API access"""

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

    def test_retrieve_services(self):
        """Test retrieving services for non-admin user"""
        create_service(url='http://example.com', name='Test Service')
        create_service(url='http://example2.com', name='Test Service 2')

        res = self.client.get(SERVICES_URL_LIST)
        services = Service.objects.all()
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(len(res.data), services.count())

    def test_retrieve_service_id(self):
        """Test retrieving service by ID for non-admin user"""
        service = create_service(url='http://example.com', name='Test Service')
        res = self.client.get(detail_url(service.id))

        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data['id'], service.id)

    def test_create_service_not_allowed(self):
        """
        Test that creating service is not allowed
        for non-admin users
        """
        payload = {
            'name': 'Test Service',
            'description': 'Test Service',
            'type': 'utility',
            'paid': False,
            'url': 'http://example.com',
        }
        res = self.client.post(SERVICES_URL_LIST, payload)
        self.assertEqual(res.status_code, status.HTTP_403_FORBIDDEN)

    def test_delete_service_not_allowed(self):
        """Test deleting service fails for non-admin users"""
        service = create_service(url='http://example.com', name='Test Service')
        res = self.client.delete(detail_url(service.id))
        self.assertEqual(res.status_code, status.HTTP_403_FORBIDDEN)

    def test_patch_service_not_allowed(self):
        """Test patching service fails for non-admin users"""
        service = create_service(url='http://example.com', name='Test Service')
        res = self.client.patch(detail_url(service.id), {'paid': True})
        self.assertEqual(res.status_code, status.HTTP_403_FORBIDDEN)


class AdminServiceAPITests(TestCase):
    """Test admin API access for services API"""

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

    def test_create_service_admin(self):
        """Test creating service works for admin"""
        payload = {
            'name': 'Test Service',
            'description': 'Test Service',
            'type': 'utility',
            'paid': False,
            'url': 'http://example.com',
        }
        res = self.client.post(SERVICES_URL_LIST, payload)
        self.assertEqual(res.status_code, status.HTTP_201_CREATED)

    def test_retrieve_services_admin(self):
        """Test retrieving services for admin user"""
        create_service(url='http://example.com', name='Test Service')
        create_service(url='http://example2.com', name='Test Service 2')

        res = self.client.get(SERVICES_URL_LIST)
        services = Service.objects.all()
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(len(res.data), services.count())

    def test_retrieve_service_id_admin(self):
        """Test retrieving service by ID for admin user"""
        service = create_service(url='http://example.com', name='Test Service')
        res = self.client.get(detail_url(service.id))

        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data['id'], service.id)

    def test_delete_service_admin(self):
        """Test deleting service passes for admin users"""
        service = create_service(url='http://example.com', name='Test Service')
        res = self.client.delete(detail_url(service.id))
        self.assertEqual(res.status_code, status.HTTP_204_NO_CONTENT)

    def test_patch_service_admin(self):
        """Test patching service passes for admin users"""
        service = create_service(url='http://example.com', name='Test Service')
        res = self.client.patch(detail_url(service.id), {'paid': True})
        self.assertEqual(res.status_code, status.HTTP_200_OK)

"""
Views for the user API
"""
from django.contrib.auth import get_user_model
from keycloak.exceptions import (
    KeycloakAuthenticationError,
    KeycloakConnectionError,
    KeycloakError
)
from rest_framework import serializers
from rest_framework import generics, permissions, status, filters
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework.settings import api_settings
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.pagination import PageNumberPagination
from django_filters import rest_framework as django_filters
from utils.keycloak import KeycloakAuthentication
from utils.super_user_or_api_key import IsSuperUserOrAPIKeyUser
from .serializers import (
    UserSerializer,
    KeycloakAuthTokenSerializer,
    AdminUserSerializer
)
from .filters import UserFilter
from rest_framework.generics import RetrieveAPIView
import logging

logger = logging.getLogger(__name__)


class AdminUserPagination(PageNumberPagination):
    """Custom pagination for admin user list"""
    page_size = 25
    page_size_query_param = 'page_size'
    max_page_size = 100


def create_user(**params):
    """Helper function to create a user"""
    return get_user_model().objects.create_user(**params)


def update_keycloak_user(user, data):
    """Helper method to update the user in Keycloak"""
    try:
        # Retrieve the Keycloak user ID based on the Django user
        keycloak_user_id = settings.KEYCLOAK_ADMIN.get_user_id(user.username)
        # Prepare the Keycloak update payload
        keycloak_payload = {
            "firstName": data.get("first_name", user.first_name),
            "lastName": data.get("last_name", user.last_name),
            "email": user.email,
            "username": user.username,
            "enabled": user.is_active,
        }

        # Update the Keycloak user
        settings.KEYCLOAK_ADMIN.update_user(keycloak_user_id, keycloak_payload)

    except KeycloakAuthenticationError:
        raise ValidationError(
            {'detail': 'Authentication with Keycloak failed.'}, code=401
        )

    except KeycloakConnectionError:
        raise ValidationError(
            {'detail': 'Unable to connect to Keycloak server.'}, code=503
        )

    except KeycloakError as e:
        raise ValidationError(
            {'detail': f'Keycloak error: {str(e)}'}, code=400
        )


class RetrieveUserView(RetrieveAPIView):
    """Retrieve a user by ID"""
    queryset = get_user_model().objects.all()
    serializer_class = UserSerializer
    authentication_classes = (KeycloakAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)
    lookup_field = "id"

    def get(self, request, *args, **kwargs):
        logger.debug(
            f"User {request.user} requested user details for id={kwargs.get('id')}"
        )
        try:
            return super().get(request, *args, **kwargs)
        except Exception as e:
            logger.error(f"Error retrieving user id={kwargs.get('id')}: {e}")
            raise


class CreateUserView(generics.CreateAPIView):
    """Create a new user in the system"""
    serializer_class = UserSerializer

    def create(self, request, *args, **kwargs):
        logger.debug(f"User creation requested with data: {request.data}")
        try:
            response = super().create(request, *args, **kwargs)
            logger.debug(f"User created successfully: {response.data}")
            return response
        except Exception as e:
            logger.error(f"User creation failed: {e}")
            raise


class NetworkAdminLoginView(ObtainAuthToken):
    """Generates a token for network admins"""
    serializer_class = KeycloakAuthTokenSerializer
    renderer_classes = api_settings.DEFAULT_RENDERER_CLASSES

    def post(self, request, *args, **kwargs):
        logger.debug(f"Network admin login attempt for data: {request.data}")
        serializer = self.serializer_class(
            data=request.data, context={'request': request}
        )
        if not serializer.is_valid():
            logger.error(
                f"Network admin login failed validation: {serializer.errors}"
            )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        user = serializer.validated_data.get('user')
        if not user or not user.has_perm('core.network_admin'):
            logger.error(f"User {user} does not have network admin privileges.")
            return Response(
                {'detail': 'User does not have network admin privileges.'},
                status=status.HTTP_403_FORBIDDEN
            )
        keycloak_token = serializer.validated_data.get('token')
        refresh_token = serializer.validated_data.get('refresh_token')
        expires_in = serializer.validated_data.get('expires_in')
        logger.debug(f"Network admin {user} logged in successfully.")
        return Response({
            'token': keycloak_token,
            'refresh_token': refresh_token,
            'expires_in': expires_in
        }, status=status.HTTP_200_OK)


class CreateTokenView(ObtainAuthToken):
    """Create a new auth token for the user"""
    serializer_class = KeycloakAuthTokenSerializer
    renderer_classes = api_settings.DEFAULT_RENDERER_CLASSES

    def post(self, request, *args, **kwargs):
        logger.debug(f"Token creation requested for data: {request.data}")
        serializer = self.serializer_class(
            data=request.data, context={'request': request}
        )
        if not serializer.is_valid():
            logger.error(f"Token creation failed validation: {serializer.errors}")
            return Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )
        keycloak_token = serializer.validated_data.get('token')
        refresh_token = serializer.validated_data.get('refresh_token')
        expires_in = serializer.validated_data.get('expires_in')
        logger.debug(
            f"Token created for user: {serializer.validated_data.get('user')}"
        )
        return Response({
            'token': keycloak_token,
            'refresh_token': refresh_token,
            'expires_in': expires_in
        }, status=status.HTTP_200_OK)


class RefreshTokenView(APIView):
    """View to refresh the access token"""
    serializer = KeycloakAuthTokenSerializer()

    def post(self, request, *args, **kwargs):
        logger.debug(f"Refresh token requested: {request.data}")
        refresh_token = request.data.get('refresh_token')
        if not refresh_token:
            logger.error("Refresh token missing in request.")
            return Response({'detail': 'Refresh token required.'}, status=400)
        try:
            token_data = self.serializer.refresh_token_if_needed(refresh_token)
            logger.debug("Token refreshed successfully.")
            return Response(token_data, status=200)
        except serializers.ValidationError as e:
            logger.error(f"Token refresh failed: {e.detail}")
            return Response(e.detail, status=status.HTTP_400_BAD_REQUEST)


class ManageUserView(generics.RetrieveUpdateAPIView):
    """Manage the authenticated user"""
    serializer_class = UserSerializer
    authentication_classes = (KeycloakAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)

    def get_object(self):
        """Retrieve the authenticated user"""
        return self.request.user

    def update(self, request, *args, **kwargs):
        user = self.get_object()
        partial = kwargs.pop('partial', False)
        logger.debug(
            f"User {user} profile update requested with data: {request.data}"
        )
        serializer = self.get_serializer(
            user,
            data=request.data,
            partial=partial
        )
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        try:
            update_keycloak_user(user, request.data)
            logger.debug(f"User {user} profile updated successfully.")
        except Exception as e:
            logger.error(f"Failed to update Keycloak user for {user}: {e}")
        return Response(serializer.data)

    def patch(self, request, *args, **kwargs):
        """Override the patch method"""
        return self.update(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        """Override the put method"""
        return self.update(request, *args, **kwargs)


class UserSearchView(generics.ListAPIView):
    """
    API endpoint that allows users to be searched by a query string.
    For example: GET /api/users/search/?search=john
    """
    serializer_class = UserSerializer
    authentication_classes = (KeycloakAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)
    queryset = get_user_model().objects.all()

    # Use the SearchFilter backend
    filter_backends = [filters.SearchFilter]
    # Allow searching by username
    search_fields = ['username']

    def get(self, request, *args, **kwargs):
        logger.debug(
            f"User search requested by {request.user} with params: {request.query_params}"
        )
        try:
            return super().get(request, *args, **kwargs)
        except Exception as e:
            logger.error(f"User search failed: {e}")
            raise


class AdminUserListView(generics.ListAPIView):
    """
    Admin endpoint to list all users with filtering and search.
    Supports filtering by has_imsi, has_wallet, is_active, is_staff, is_superuser
    and searching by username, email, first_name, last_name.
    """
    serializer_class = AdminUserSerializer
    authentication_classes = (KeycloakAuthentication,)
    permission_classes = (IsSuperUserOrAPIKeyUser,)
    queryset = get_user_model().objects.all()
    filter_backends = [django_filters.DjangoFilterBackend]
    filterset_class = UserFilter
    pagination_class = AdminUserPagination

    def get_queryset(self):
        """Optimize queryset with prefetch for wallet data"""
        return get_user_model().objects.prefetch_related('wallet_set').all()

    def get(self, request, *args, **kwargs):
        logger.debug(
            f"Admin user list requested by {request.user} with params: {request.query_params}"
        )
        try:
            return super().get(request, *args, **kwargs)
        except Exception as e:
            logger.error(f"Admin user list failed: {e}")
            raise


class AdminUserDetailView(generics.RetrieveAPIView):
    """
    Admin endpoint to retrieve detailed information about a specific user.
    """
    serializer_class = AdminUserSerializer
    authentication_classes = (KeycloakAuthentication,)
    permission_classes = (IsSuperUserOrAPIKeyUser,)
    queryset = get_user_model().objects.all()
    lookup_field = 'pk'

    def get_queryset(self):
        """Optimize queryset with prefetch for wallet data"""
        return get_user_model().objects.prefetch_related('wallet_set').all()

    def get(self, request, *args, **kwargs):
        logger.debug(
            f"Admin user detail requested by {request.user} for user {kwargs.get('pk')}"
        )
        try:
            return super().get(request, *args, **kwargs)
        except Exception as e:
            logger.error(f"Admin user detail failed: {e}")
            raise


class AdminUserUpdateView(generics.UpdateAPIView):
    """
    Admin endpoint to update user information.
    Supports both PATCH and PUT methods.
    """
    serializer_class = AdminUserSerializer
    authentication_classes = (KeycloakAuthentication,)
    permission_classes = (IsSuperUserOrAPIKeyUser,)
    queryset = get_user_model().objects.all()
    lookup_field = 'pk'

    def update(self, request, *args, **kwargs):
        user = self.get_object()
        partial = kwargs.pop('partial', False)
        logger.debug(
            f"Admin user update requested by {request.user} for user {user.id} with data: {request.data}"
        )
        serializer = self.get_serializer(
            user,
            data=request.data,
            partial=partial
        )
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        try:
            # Only update Keycloak for non-admin fields
            keycloak_data = {
                'first_name': request.data.get('first_name', user.first_name),
                'last_name': request.data.get('last_name', user.last_name),
            }
            update_keycloak_user(user, keycloak_data)
            logger.debug(f"User {user.id} updated successfully by admin.")
        except Exception as e:
            logger.error(f"Failed to update Keycloak user for {user}: {e}")
        return Response(serializer.data)

    def patch(self, request, *args, **kwargs):
        """Override the patch method"""
        kwargs['partial'] = True
        return self.update(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        """Override the put method"""
        kwargs['partial'] = False
        return self.update(request, *args, **kwargs)

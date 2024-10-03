"""
Views for the user API
"""
from rest_framework import generics, permissions, status
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.response import Response
from rest_framework.settings import api_settings

from utils.keycloak import KeycloakAuthentication
from .serializers import (
    UserSerializer,
    KeycloakAuthTokenSerializer
)


class CreateUserView(generics.CreateAPIView):
    """Create a new user in the system"""
    serializer_class = UserSerializer


class CreateTokenView(ObtainAuthToken):
    """Create a new auth token for the user"""
    serializer_class = KeycloakAuthTokenSerializer
    renderer_classes = api_settings.DEFAULT_RENDERER_CLASSES

    def post(self, request, *args, **kwargs):
        # Use the KeycloakAuthTokenSerializer
        serializer = self.serializer_class(
            data=request.data, context={'request': request}
        )
        if not serializer.is_valid():
            return Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )

        keycloak_token = serializer.validated_data.get('token')
        # Return response based on the type of authentication
        return Response({
            'token': keycloak_token,  # Keycloak token (access token)
        }, status=status.HTTP_200_OK)


class ManageUserView(generics.RetrieveUpdateAPIView):
    """Manage the authenticated user"""
    serializer_class = UserSerializer
    authentication_classes = (KeycloakAuthentication,)
    permission_classes = (permissions.IsAuthenticated,)

    def get_object(self):
        """Retrieve the authenticated user"""
        return self.request.user

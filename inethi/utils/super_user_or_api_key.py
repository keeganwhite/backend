from rest_framework.permissions import BasePermission
from .authentication_api_key import APIKeyAuthentication


class IsSuperUserOrAPIKeyUser(BasePermission):
    """
    Custom permission to allow access to superusers (via Keycloak)
    or users authenticated via API Key.
    """

    def has_permission(self, request, view):
        # Allow superusers authenticated via Keycloak
        if (
                request.user
                and request.user.is_authenticated
                and request.user.is_superuser
        ):
            return True

        # Allow users authenticated via API Key
        api_key_auth = APIKeyAuthentication()
        api_key_auth_result = api_key_auth.authenticate(request)
        if api_key_auth_result:
            return True

        # Otherwise, deny access
        return False

from rest_framework.permissions import BasePermission
from .super_user_or_api_key import IsSuperUserOrAPIKeyUser


class IsSuperUserOrAPIKeyUserOrNetworkAdmin(BasePermission):
    """
    Allows access if the user is either:
      - A superuser or API key user (via IsSuperUserOrAPIKeyUser), or
      - Has the 'network_admin' permission.
    """

    def has_permission(self, request, view):
        # First check the existing permission.
        if IsSuperUserOrAPIKeyUser().has_permission(request, view):
            return True

        # Then check if the user has the 'network_admin' permission.
        return (request.user and request.user.is_authenticated and
                request.user.has_perm('core.network_admin'))

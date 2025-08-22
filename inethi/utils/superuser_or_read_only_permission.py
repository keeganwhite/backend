from rest_framework.permissions import BasePermission, SAFE_METHODS


class IsSuperUserOrReadOnly(BasePermission):
    """
    Custom permission to allow superusers to create, update, and delete,
    but allow read-only access for other logged-in users.
    """
    # Allow create, update, and delete for superusers only
    # Allow read-only methods for all authenticated users

    def has_permission(self, request, view):
        if request.method in SAFE_METHODS:
            return request.user.is_authenticated
        return request.user.is_superuser

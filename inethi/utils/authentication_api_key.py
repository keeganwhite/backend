from django.contrib.auth import get_user_model
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from api_key.models import APIKey

User = get_user_model()


class APIKeyAuthentication(BaseAuthentication):
    """Custom authentication using API Keys"""

    def authenticate(self, request):
        token = request.headers.get("Authorization")

        if (
                not token
                or not token.startswith("ApiKey ")
        ):
            return None

        api_key = token[len("ApiKey "):]  # Remove "ApiKey " prefix

        try:
            api_key_obj = APIKey.objects.get(key=api_key, is_active=True)
            return (api_key_obj.user, None)  # Authenticated via API Key
        except APIKey.DoesNotExist:
            raise AuthenticationFailed("Invalid API Key")

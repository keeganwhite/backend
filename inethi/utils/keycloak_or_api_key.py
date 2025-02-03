from django.contrib.auth import get_user_model
from rest_framework.authentication import BaseAuthentication
from django.conf import settings
from rest_framework.exceptions import AuthenticationFailed, NotAuthenticated
from api_key.models import APIKey

User = get_user_model()


class KeycloakOrAPIKeyAuthentication(BaseAuthentication):
    """
    Allow authentication using either Keycloak tokens or API keys
    """

    def authenticate(self, request):
        token = request.headers.get("Authorization")

        # Check if an API key is provided
        if token and token.startswith("ApiKey "):
            api_key = token[len("ApiKey "):]  # Remove prefix
            try:
                api_key_obj = APIKey.objects.get(key=api_key, is_active=True)
                return (api_key_obj.user, None)  # Authenticated via API Key
            except APIKey.DoesNotExist:
                raise AuthenticationFailed("Invalid API Key")

        # If no API key was found, fallback to Keycloak authentication
        if not token:
            raise NotAuthenticated("No token provided", code=401)

        if token.startswith("Bearer "):
            token = token[len("Bearer "):]

        keycloak_openid = settings.KEYCLOAK_OPENID
        try:
            # Verify token with Keycloak
            user_info = keycloak_openid.userinfo(token)
            email = user_info.get('email')
            username = user_info.get('preferred_username')  # username fallback

            # Find the user by email or username
            user = None
            if email:
                user = get_user_model().objects.filter(
                    email=email
                ).first()
            if not user and username:
                user = get_user_model().objects.filter(
                    username=username
                ).first()

            if not user:
                raise AuthenticationFailed('User not found')

            # Return the user and the token
            return (user, token)
        except Exception as e:
            raise NotAuthenticated(
                f"Invalid Keycloak token: {str(e)}",
                code=401
            )

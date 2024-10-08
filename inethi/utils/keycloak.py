from django.contrib.auth import get_user_model
from rest_framework.authentication import BaseAuthentication
from django.conf import settings
from rest_framework.exceptions import AuthenticationFailed, NotAuthenticated


class KeycloakAuthentication(BaseAuthentication):
    """Custom authentication using Keycloak tokens"""

    def authenticate(self, request):
        token = request.headers.get('Authorization')

        if not token:
            raise NotAuthenticated('No token provided', code=401)

        # Strip 'Bearer ' prefix if present
        if token.startswith('Bearer '):
            token = token[len('Bearer '):]
        keycloak_openid = settings.KEYCLOAK_OPENID

        try:
            # Verify token with Keycloak
            user_info = keycloak_openid.userinfo(token)
            email = user_info.get('email')

            # Find or create the user in Django
            user = get_user_model().objects.filter(email=email).first()
            if not user:
                print('Cannot find user')
                raise AuthenticationFailed(
                    'User not found'
                )

            # Return the user and the token
            return (user, token)

        except Exception as e:
            raise NotAuthenticated(
                f'Invalid Keycloak token: {str(e)}'
            )

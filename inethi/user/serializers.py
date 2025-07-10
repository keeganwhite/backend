"""
Serializers for user views
"""
from django.contrib.auth import (
    get_user_model,
)
from django.utils.translation import gettext as _
from rest_framework import serializers
import logging
from inethi.settings import KEYCLOAK_OPENID
from keycloak.exceptions import (
    KeycloakAuthenticationError,
    KeycloakConnectionError,
    KeycloakError
)

logger = logging.getLogger(__name__)


class UserSerializer(serializers.ModelSerializer):
    """Serializer for the user model"""
    email = serializers.EmailField(required=False, allow_blank=True)

    class Meta:
        model = get_user_model()
        fields = [
            'id',
            'email',
            'username',
            'first_name',
            'last_name',
            'phone_number',
            'password'
        ]
        extra_kwargs = {
            'password': {'write_only': True, 'min_length': 5},
            'username': {'required': True},
            'phone_number': {'required': False},  # Optional phone number
            'email': {'required': False},  # Optional email
        }

    def validate_email(self, value):
        if not value or value.strip() == "":
            logger.info("No email provided, will generate default email.")
            return None
        return value

    def create(self, validated_data):
        email = validated_data.get("email")
        username = validated_data.get("username")
        validated_data["email"] = email or f"{username}@inethi.com"
        logger.info(
            f"Creating user: {username} with email: {validated_data['email']}"
        )
        try:
            user = get_user_model().objects.create_user(**validated_data)
            logger.info(f"User created successfully: {user}")
            return user
        except Exception as e:
            logger.error(f"User creation failed: {e}")
            raise

    def update(self, instance, validated_data):
        """Update a user with encrypted password"""
        password = validated_data.pop('password', None)
        logger.info(f"Updating user: {instance} with data: {validated_data}")
        user = super().update(instance, validated_data)
        if password:
            user.set_password(password)
            user.save()
            logger.info(f"Password updated for user: {user}")
        return user


class KeycloakAuthTokenSerializer(serializers.Serializer):
    """Serializer for the Keycloak user auth token"""
    token = serializers.CharField(required=False)
    email = serializers.EmailField(required=False)
    username = serializers.CharField(required=False)
    password = serializers.CharField(
        style={'input_type': 'password'},
        trim_whitespace=False,
        required=False
    )

    def validate(self, attrs):
        """
        Validate and authenticate the user using either
        Keycloak token or email/password
        """
        token = attrs.get('token')
        email = attrs.get('email')
        username = attrs.get('username')
        password = attrs.get('password')
        expires_in = attrs.get('expires_in')
        refresh_token = attrs.get('refresh_token')
        try:
            # Handle Keycloak token authentication
            keycloak_openid = KEYCLOAK_OPENID

            if username and not email:
                # Look up the email based on the username
                user = get_user_model().objects.filter(
                    username=username
                ).first()
                if not user:
                    logger.error(f"User with username {username} does not exist.")
                    raise serializers.ValidationError(
                        "User with this username does not exist."
                    )
                email = user.email

            if email and password:
                # Handle email/password authentication with Keycloak
                logger.info(f"Authenticating user {email} with Keycloak.")
                token_response = keycloak_openid.token(
                    username=email,
                    password=password
                )
                # Extract the access token from the response
                token = token_response.get('access_token')
                refresh_token = token_response.get('refresh_token')
                expires_in = token_response.get('expires_in')
            if token:
                # Verify token and introspect its validity
                user_info = keycloak_openid.userinfo(token)
                if not keycloak_openid.introspect(token).get('active'):
                    logger.error("Token is invalid or expired.")
                    raise serializers.ValidationError(
                        'Token is invalid or expired.'
                    )

                # Fetch user by email from the token payload
                email = user_info.get('email')
                user, created = get_user_model().objects.get_or_create(email=email)

                if not user:
                    logger.error("User does not exist in the system.")
                    raise serializers.ValidationError(
                        _('User does not exist in the system.'),
                        code='authentication'
                    )

                attrs['refresh_token'] = refresh_token
                attrs['expires_in'] = expires_in
                attrs['user'] = user
                attrs['token'] = token
                logger.info(f"Token validated for user: {user}")
                return attrs

            else:
                logger.error(
                    'Must include either token or email/username and password.'
                )
                raise serializers.ValidationError(
                    'Must include either token or email/username and password.'
                )
        except KeycloakAuthenticationError:
            logger.error('Invalid token/unable to authenticate.')
            raise serializers.ValidationError(
                {'detail': 'Invalid token/unable to authenticate.'},
                code=401
            )
        except KeycloakConnectionError:
            logger.error('Unable to connect to Keycloak server.')
            raise serializers.ValidationError(
                {'detail': 'Unable to connect to Keycloak server.'},
                code=503
            )
        except KeycloakError as e:
            logger.error(f'Keycloak error: {str(e)}')
            raise serializers.ValidationError(
                {'detail': f'Keycloak error: {str(e)}'},
                code=500
            )
        except Exception as e:
            logger.error(f'Invalid credentials: {str(e)}')
            raise serializers.ValidationError(
                {'detail': f'Invalid credentials: {str(e)}'},
                code=400
            )

    def refresh_token_if_needed(self, refresh_token):
        """Refresh Keycloak token"""
        try:
            keycloak_openid = KEYCLOAK_OPENID
            refreshed_token_response = keycloak_openid.refresh_token(
                refresh_token
            )
            logger.info("Token refreshed successfully.")
            return {
                'access_token': refreshed_token_response.get('access_token'),
                'refresh_token': refreshed_token_response.get('refresh_token'),
                'expires_in': refreshed_token_response.get('expires_in')
            }

        except KeycloakError as e:
            logger.error(f'Failed to refresh token: {str(e)}')
            raise serializers.ValidationError(
                f'Failed to refresh token: {str(e)}'
            )

"""
Serializers for user views
"""
from django.contrib.auth import (
    get_user_model,
)
from django.utils.translation import gettext as _

from rest_framework import serializers

from inethi.settings import KEYCLOAK_OPENID
from keycloak.exceptions import (
    KeycloakAuthenticationError,
    KeycloakConnectionError,
    KeycloakError
)


class UserSerializer(serializers.ModelSerializer):
    """Serializer for the user model"""
    class Meta:
        model = get_user_model()
        fields = ['email', 'username', 'first_name', 'last_name', 'password']
        extra_kwargs = {
            'password': {'write_only': True, 'min_length': 5},
            'username': {'required': True}
        }

    def create(self, validated_data):
        """Create a new user with encrypted password."""
        return get_user_model().objects.create_user(**validated_data)

    def update(self, instance, validated_data):
        """Update a user with encrypted password."""
        password = validated_data.pop('password', None)
        user = super().update(instance, validated_data)
        if password:
            user.set_password(password)
            user.save()
        return user


class KeycloakAuthTokenSerializer(serializers.Serializer):
    """Serializer for the Keycloak user auth token"""
    token = serializers.CharField(required=False)
    email = serializers.EmailField(required=False)
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
        password = attrs.get('password')
        try:
            # Handle Keycloak token authentication
            keycloak_openid = KEYCLOAK_OPENID

            if email and password:
                # Handle email/password authentication with Keycloak
                token_response = keycloak_openid.token(
                    username=email,
                    password=password
                )
                # Extract the access token from the response
                token = token_response.get('access_token')
            if token:
                # Verify token and introspect its validity
                user_info = keycloak_openid.userinfo(token)
                if not keycloak_openid.introspect(token).get('active'):
                    raise serializers.ValidationError(
                        'Token is invalid or expired.'
                    )

                # Fetch user by email from the token payload
                email = user_info.get('email')
                user = get_user_model().objects.get_or_create(email=email)

                if not user:
                    raise serializers.ValidationError(
                        _('User does not exist in the system.'),
                        code='authentication'
                    )

                attrs['user'] = user
                attrs['token'] = token
                return attrs

            else:
                raise serializers.ValidationError(
                    'Must include either token or email and password.'
                )
        except KeycloakAuthenticationError:
            raise serializers.ValidationError(
                {'detail': 'Invalid token/unable to authenticate.'},
                code=401
            )
        except KeycloakConnectionError:
            raise serializers.ValidationError(
                {'detail': 'Unable to connect to Keycloak server.'},
                code=503
            )
        except KeycloakError as e:
            raise serializers.ValidationError(
                {'detail': f'Keycloak error: {str(e)}'},
                code=500
            )
        except Exception as e:
            raise serializers.ValidationError(
                {'detail': f'Invalid credentials: {str(e)}'},
                code=400
            )

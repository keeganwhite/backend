"""
Database models
"""
from keycloak.exceptions import (
    KeycloakAuthenticationError,
    KeycloakConnectionError,
    KeycloakError
)
from django.db import models
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin
)
from rest_framework.exceptions import ValidationError

from django.conf import settings


class UserManager(BaseUserManager):
    """Manager for users"""

    def create_user(self, email, password=None, **extra_fields):
        """Create a new user"""
        if not email:
            raise ValueError('Users must have an email address')

        # create Django User
        user = self.model(email=self.normalize_email(email), **extra_fields)
        user.set_password(password)
        user.save(using=self._db)

        # create Keycloak user
        try:
            # Create a new Keycloak user
            settings.KEYCLOAK_ADMIN.create_user({
                "email": email,
                "username": email,
                "enabled": True,
                "credentials": [
                    {"value": password,
                     "type": "password",
                     "temporary": False}
                ],
                "firstName": extra_fields.get("first_name", ""),
                "lastName": extra_fields.get("last_name", "")
            })
        except KeycloakAuthenticationError:
            # Handle authentication failure (e.g., incorrect admin credentials)
            raise ValidationError(
                {'detail': 'Authentication with Keycloak failed.'}, code=401
            )

        except KeycloakConnectionError:
            # Handle connection failure (e.g., Keycloak server is down)
            raise ValidationError(
                {'detail': 'Unable to connect to Keycloak server.'}, code=503
            )

        except KeycloakError as e:
            # Handle generic Keycloak error, pass along the details
            raise ValidationError(
                {'detail': f'Keycloak error: {str(e)}'}, code=400
            )

        return user

    def create_superuser(self, email, password):
        """Create and return a new superuser"""
        user = self.create_user(email, password)
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user


class User(AbstractBaseUser, PermissionsMixin):
    """User in the system"""
    email = models.EmailField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    USERNAME_FIELD = 'email'
    objects = UserManager()

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

    def create_user(self, email, username, password=None, **extra_fields):
        """Create a new user"""
        if not email:
            raise ValueError('Users must have an email address')
        if not username:
            raise ValueError('Users must have a username')

        # Ensure the username is unique
        if self.model.objects.filter(username=username).exists():
            raise ValueError('Username must be unique')

        # Create Django User
        user = self.model(
            email=self.normalize_email(email),
            username=username,
            **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)

        # Create Keycloak user
        try:
            # Create a new Keycloak user
            settings.KEYCLOAK_ADMIN.create_user({
                "email": email,
                "username": username,
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
            raise ValidationError(
                {'detail': 'Authentication with Keycloak failed.'}, code=401
            )
        except KeycloakConnectionError:
            raise ValidationError(
                {'detail': 'Unable to connect to Keycloak server.'}, code=503
            )
        except KeycloakError as e:
            raise ValidationError(
                {'detail': f'Keycloak error: {str(e)}'}, code=400
            )

        return user

    def create_superuser(self, email, username, password):
        """Create and return a new superuser"""
        user = self.create_user(email, username, password)
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)
        return user


class User(AbstractBaseUser, PermissionsMixin):
    """User in the system"""
    email = models.EmailField(max_length=255, unique=True)
    username = models.CharField(max_length=255, unique=True)
    first_name = models.CharField(max_length=255, blank=True, null=True)
    last_name = models.CharField(max_length=255, blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'  # this is used for auth purposes
    REQUIRED_FIELDS = ['username']

    objects = UserManager()

    def __str__(self):
        return self.username


class Wallet(models.Model):
    """Wallet Object"""
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
    )
    name = models.CharField(max_length=255, default='default_name')
    private_key = models.CharField(max_length=255)
    address = models.CharField(max_length=255, unique=True)
    token_common_name = models.CharField(max_length=255, default='KRONE')
    token = models.CharField(max_length=255, default='KRONE')
    token_type = models.CharField(max_length=255, default='ERC-20')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.address

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
        if not username:
            raise ValueError('Users must have a username')

        # Generate email if missing or empty
        email = email or f"{username}@inethi.com"
        if not email.strip():  # Prevent empty email from being saved
            email = f"{username}@inethi.com"

        # Ensure the username is unique
        if self.model.objects.filter(username=username).exists():
            raise ValueError('Username must be unique')

        if self.model.objects.filter(email=email).exists():
            raise ValueError('Email must be unique')

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
        # If Keycloak user creation is successful, create Django user
        user = self.model(
            email=self.normalize_email(email),
            username=username,
            **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)

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
    phone_number = models.CharField(max_length=15, blank=True, null=True)
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
        return f"{self.user} at {self.address}"


class SmartContract(models.Model):
    """Smart Contract Object"""

    name = models.CharField(max_length=255)
    address = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        blank=True,
    )
    write_access = models.BooleanField(default=False)
    read_access = models.BooleanField(default=False)
    contract_type = models.CharField(max_length=255)

    class Meta:
        verbose_name = 'Smart Contract'
        verbose_name_plural = 'Smart Contracts'

    def get_child_instance(self):
        """This method returns the instance of the subclass if it exists"""
        for subclass in self.__class__.__subclasses__():
            if subclass.objects.filter(id=self.id).exists():
                return subclass.objects.get(id=self.id)
        return self  # Return self if no subclass instance is found

    def __str__(self):
        return f"{self.name} at {self.address}"


class FaucetSmartContract(SmartContract):
    """
    Faucet Smart Contract Model that adds
    method tracking functionality
    """

    owner_address = models.CharField(max_length=255)
    gimme = models.BooleanField(default=False)
    give_to = models.BooleanField(default=False)
    next_balance = models.BooleanField(default=False)
    next_time = models.BooleanField(default=False)
    registry_address = models.CharField(max_length=255, blank=True)

    class Meta:
        verbose_name = 'Faucet Smart Contract'
        verbose_name_plural = 'Faucet Smart Contracts'

    def save(self, *args, **kwargs):
        self.contract_type = 'eth faucet'
        super().save(*args, **kwargs)


class AccountsIndexContract(SmartContract):
    """
    Account Index smart contract model that adds
    method tracking functionality
    """

    owner_address = models.CharField(max_length=255)
    entry = models.BooleanField(default=False)
    entry_count = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    activate = models.BooleanField(default=False)
    deactivate = models.BooleanField(default=False)
    add = models.BooleanField(default=False)
    remove = models.BooleanField(default=False)

    class Meta:
        verbose_name = 'Account Index Smart Contract'
        verbose_name_plural = 'Account Index Smart Contracts'

    def save(self, *args, **kwargs):
        self.contract_type = 'account index'
        super().save(*args, **kwargs)


class Service(models.Model):
    """
    Service Object that stores data about a service
    offered by iNethi
    """
    TYPE_ENTERTAINMENT = 'entertainment'
    TYPE_LEARNING = 'learning'
    TYPE_UTILITY = 'utility'

    TYPE_CHOICES = [
        (TYPE_ENTERTAINMENT, 'Entertainment'),
        (TYPE_LEARNING, 'Learning'),
        (TYPE_UTILITY, 'Utility'),
    ]

    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    url = models.URLField(unique=True)
    type = models.CharField(
        max_length=50,
        choices=TYPE_CHOICES,
        default=TYPE_UTILITY,
    )
    paid = models.BooleanField(default=False)


class Transaction(models.Model):
    """
    Transaction Object
    """
    CATEGORY_CHOICES = [
        ('TRANSFER', 'Transfer'),
        ('REWARD', 'Reward'),
        ('PAYMENT', 'Payment'),
        ('OTHER', 'Other'),
    ]
    sender = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='sent_transactions'
    )
    recipient = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='received_transactions',
        null=True,
        blank=True
    )
    recipient_address = models.CharField(max_length=256)
    amount = models.DecimalField(max_digits=18, decimal_places=8)
    transaction_hash = models.CharField(max_length=256)
    block_number = models.CharField(max_length=256)
    block_hash = models.CharField(max_length=256)
    gas_used = models.DecimalField(max_digits=18, decimal_places=8)
    category = models.CharField(
        max_length=50,
        choices=CATEGORY_CHOICES,
        default='TRANSFER'
    )
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Transaction from {self.sender} to {self.recipient_address}"

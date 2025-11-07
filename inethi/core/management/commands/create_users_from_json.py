"""
Django command to create users from a JSON file with wallets and network admin permissions.
"""
import json
import os
import logging
from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth import get_user_model
from django.db import transaction
from django.conf import settings
from core.models import Wallet
from utils.crypto import encrypt_private_key, decrypt_private_key
from utils.crypto import CryptoUtils

User = get_user_model()
logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """Django command to create users from JSON file with wallets."""

    help = 'Creates users from JSON file with wallets and network admin permissions'

    def add_arguments(self, parser):
        """Add command arguments."""
        parser.add_argument(
            'json_file',
            type=str,
            help='Path to JSON file containing user data'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be created without actually creating users'
        )

    def create_wallet_for_user(self, user, wallet_name='default'):
        """
        Create a wallet for a user using the same logic as the wallet serializer.
        Returns the created wallet or None if creation failed.
        """
        try:
            # Use utility script to create wallet
            crypto_utils = CryptoUtils(
                contract_abi_path=settings.ABI_FILE_PATH,
                contract_address=settings.CONTRACT_ADDRESS,
                registry=settings.FAUCET_AND_INDEX_ENABLED,
                faucet=settings.FAUCET_AND_INDEX_ENABLED,
            )
            wallet_info = crypto_utils.create_wallet()

            # Ensure wallet_info contains the expected keys
            if 'private_key' not in wallet_info or 'address' not in wallet_info:
                logger.error("Wallet creation failed: missing keys in response")
                return None

            p_key = wallet_info['private_key']
            w_addr = wallet_info['address']
            encrypted_private_key = encrypt_private_key(p_key)

            wallet_data = {
                'user': user,
                'name': wallet_name,
                'private_key': encrypted_private_key,
                'address': w_addr,
                'token_common_name': 'KRONE',
                'token': 'KRONE',
                'token_type': 'ERC-20',
            }
            logger.debug(f"Wallet data: {wallet_data}")

            if settings.FAUCET_AND_INDEX_ENABLED:
                try:
                    # Add the wallet to the account index for Krone
                    account_index_creator = Wallet.objects.get(
                        address=settings.ACCOUNT_INDEX_ADMIN_WALLET_ADDRESS
                    )
                    p_key_admin = decrypt_private_key(account_index_creator.private_key)

                    # Create new CryptoUtils instance for registry operations
                    registry_crypto = CryptoUtils(
                        contract_abi_path=settings.ABI_FILE_PATH,
                        contract_address=settings.CONTRACT_ADDRESS,
                        registry=settings.FAUCET_AND_INDEX_ENABLED,
                        faucet=settings.FAUCET_AND_INDEX_ENABLED,
                    )

                    # Add the wallet to the account index for Krone
                    registry_crypto.registry_add(p_key_admin, w_addr)

                    # send the account gas
                    faucet_creator = Wallet.objects.get(
                        address=settings.FAUCET_ADMIN_WALLET_ADDRESS
                    )
                    p_key_faucet = decrypt_private_key(faucet_creator.private_key)

                    # Add small delay between transactions to avoid nonce conflicts
                    import time
                    time.sleep(1.0)

                    # Create new CryptoUtils instance for faucet operations
                    faucet_crypto = CryptoUtils(
                        contract_abi_path=settings.ABI_FILE_PATH,
                        contract_address=settings.CONTRACT_ADDRESS,
                        registry=settings.FAUCET_AND_INDEX_ENABLED,
                        faucet=settings.FAUCET_AND_INDEX_ENABLED,
                    )
                    faucet_crypto.faucet_give_to(p_key_faucet, w_addr)
                except Exception as e:
                    logger.error(f"Error during wallet creation (registry/faucet): {e}")
                    # Continue with wallet creation even if registry/faucet fails
                    pass

            # Create the wallet
            return Wallet.objects.create(**wallet_data)

        except Exception as e:
            logger.error(f"Error creating wallet for user {user.username}: {e}")
            return None

    def handle(self, *args, **options):
        """Entry point for Django management command."""
        json_file = options['json_file']
        dry_run = options['dry_run']

        # Check if file exists
        if not os.path.exists(json_file):
            raise CommandError(f'JSON file "{json_file}" does not exist.')

        # Read and parse JSON file
        try:
            with open(json_file, 'r') as f:
                users_data = json.load(f)
        except json.JSONDecodeError as e:
            raise CommandError(f'Invalid JSON format: {str(e)}')
        except Exception as e:
            raise CommandError(f'Error reading JSON file: {str(e)}')

        # Validate JSON structure
        if not isinstance(users_data, list):
            raise CommandError('JSON file must contain a list of user objects.')

        if dry_run:
            self.stdout.write(self.style.WARNING('DRY RUN MODE - No users will be created'))

        created_users = []
        errors = []

        for i, user_data in enumerate(users_data):
            try:
                # Validate required fields (wallet_address and private_key are now optional)
                required_fields = ['username', 'password', 'email']
                missing_fields = [field for field in required_fields if field not in user_data]

                if missing_fields:
                    errors.append(f'User {i+1}: Missing required fields: {", ".join(missing_fields)}')
                    continue

                username = user_data['username']
                password = user_data['password']
                email = user_data['email']

                # Optional fields
                first_name = user_data.get('first_name', '')
                last_name = user_data.get('last_name', '')
                phone_number = user_data.get('phone_number', '')

                # Wallet fields (optional - will be auto-generated if not provided)
                wallet_address = user_data.get('wallet_address')
                private_key = user_data.get('private_key')

                if dry_run:
                    if wallet_address:
                        self.stdout.write(
                            f'Would create user: {username} ({email}) with existing wallet {wallet_address}'
                        )
                    else:
                        self.stdout.write(
                            f'Would create user: {username} ({email}) with auto-generated wallet'
                        )
                    continue

                # Create user and wallet in transaction
                with transaction.atomic():
                    # Check if user already exists
                    if User.objects.filter(username=username).exists():
                        errors.append(f'User {i+1}: Username "{username}" already exists')
                        continue

                    if User.objects.filter(email=email).exists():
                        errors.append(f'User {i+1}: Email "{email}" already exists')
                        continue

                    # Check if wallet address already exists (only if provided)
                    if wallet_address and Wallet.objects.filter(address=wallet_address).exists():
                        errors.append(f'User {i+1}: Wallet address "{wallet_address}" already exists')
                        continue

                    # Create user
                    user = User.objects.create_user(
                        email=email,
                        username=username,
                        password=password,
                        first_name=first_name,
                        last_name=last_name,
                        phone_number=phone_number
                    )

                    # Mark as network admin
                    user.user_permissions.add(
                        User._meta.get_field('user_permissions').related_model.objects.get(
                            codename='network_admin'
                        )
                    )

                    # Create wallet
                    if wallet_address and private_key:
                        # Use provided wallet details
                        encrypted_private_key = encrypt_private_key(private_key)
                        wallet = Wallet.objects.create(
                            user=user,
                            name='default',
                            private_key=encrypted_private_key,
                            address=wallet_address,
                            token_common_name='KRONE',
                            token='KRONE',
                            token_type='ERC-20'
                        )
                    else:
                        # Auto-generate wallet
                        wallet = self.create_wallet_for_user(user)
                        if not wallet:
                            errors.append(f'User {i+1}: Failed to create wallet for user "{username}"')
                            continue

                    created_users.append({
                        'username': username,
                        'email': email,
                        'wallet_address': wallet.address
                    })

                    if wallet_address:
                        self.stdout.write(
                            self.style.SUCCESS(
                                f'Created user "{username}" with existing wallet {wallet.address}'
                            )
                        )
                    else:
                        self.stdout.write(
                            self.style.SUCCESS(
                                f'Created user "{username}" with auto-generated wallet {wallet.address}'
                            )
                        )

            except Exception as e:
                errors.append(f'User {i+1}: {str(e)}')
                continue

        # Summary
        if dry_run:
            self.stdout.write(
                self.style.WARNING(f'Would create {len(users_data)} users')
            )
        else:
            self.stdout.write(
                self.style.SUCCESS(f'Successfully created {len(created_users)} users')
            )

            if created_users:
                self.stdout.write('\nCreated users:')
                for user in created_users:
                    self.stdout.write(f'  - {user["username"]} ({user["email"]})')

        if errors:
            self.stdout.write('\nErrors:')
            for error in errors:
                self.stdout.write(self.style.ERROR(f'  - {error}'))

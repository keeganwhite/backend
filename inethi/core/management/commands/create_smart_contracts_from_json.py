"""
Django command to create smart contracts from a JSON file and assign to superuser.
"""
import json
import os
from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth import get_user_model
from django.db import transaction
from core.models import SmartContract, FaucetSmartContract, AccountsIndexContract

User = get_user_model()


class Command(BaseCommand):
    """Django command to create smart contracts from JSON file."""

    help = 'Creates smart contracts from JSON file and assigns to specified users'

    def add_arguments(self, parser):
        """Add command arguments."""
        parser.add_argument(
            'json_file',
            type=str,
            help='Path to JSON file containing smart contract data'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be created without actually creating contracts'
        )
        parser.add_argument(
            '--default-user',
            type=str,
            help=('Default username to assign contracts to if user_name not specified in JSON '
                  '(defaults to SUPERUSER_USERNAME from env)')
        )

    def handle(self, *args, **options):
        """Entry point for Django management command."""
        json_file = options['json_file']
        dry_run = options['dry_run']
        default_user = options['default_user']

        # Get default user username from env if not provided
        if not default_user:
            default_user = os.getenv('SUPERUSER_USERNAME')
            if not default_user:
                raise CommandError('SUPERUSER_USERNAME not found in environment variables.')

        # Get default user
        try:
            User.objects.get(username=default_user)
        except User.DoesNotExist:
            raise CommandError(f'User with username "{default_user}" does not exist.')

        # Check if file exists
        if not os.path.exists(json_file):
            raise CommandError(f'JSON file "{json_file}" does not exist.')

        # Read and parse JSON file
        try:
            with open(json_file, 'r') as f:
                contracts_data = json.load(f)
        except json.JSONDecodeError as e:
            raise CommandError(f'Invalid JSON format: {str(e)}')
        except Exception as e:
            raise CommandError(f'Error reading JSON file: {str(e)}')

        # Validate JSON structure
        if not isinstance(contracts_data, list):
            raise CommandError('JSON file must contain a list of contract objects.')

        if dry_run:
            self.stdout.write(self.style.WARNING('DRY RUN MODE - No contracts will be created'))

        created_contracts = []
        errors = []

        for i, contract_data in enumerate(contracts_data):
            try:
                # Validate required fields
                required_fields = ['name', 'address', 'contract_type']
                missing_fields = [field for field in required_fields if field not in contract_data]

                if missing_fields:
                    errors.append(f'Contract {i+1}: Missing required fields: {", ".join(missing_fields)}')
                    continue

                name = contract_data['name']
                address = contract_data['address']
                contract_type = contract_data['contract_type']
                description = contract_data.get('description', '')
                write_access = contract_data.get('write_access', False)
                read_access = contract_data.get('read_access', True)

                # Get user to assign contract to
                user_name = contract_data.get('user_name', default_user)
                try:
                    user = User.objects.get(username=user_name)
                except User.DoesNotExist:
                    errors.append(f'Contract {i+1}: User "{user_name}" does not exist')
                    continue

                if dry_run:
                    self.stdout.write(
                        f'Would create contract: {name} ({contract_type}) at {address} '
                        f'assigned to user: {user_name}'
                    )
                    continue

                # Create contract in transaction
                with transaction.atomic():
                    # Check if contract already exists
                    if SmartContract.objects.filter(address=address).exists():
                        errors.append(f'Contract {i+1}: Address "{address}" already exists')
                        continue

                    # Create base contract
                    base_contract = SmartContract.objects.create(
                        name=name,
                        address=address,
                        description=description,
                        user=user,
                        write_access=write_access,
                        read_access=read_access,
                        contract_type=contract_type
                    )

                    # Create specific contract type if needed
                    if contract_type.lower() == 'faucet':
                        owner_address = contract_data.get('owner_address', '')
                        if not owner_address:
                            errors.append(f'Contract {i+1}: Faucet contract requires owner_address')
                            continue

                        FaucetSmartContract.objects.create(
                            smartcontract_ptr=base_contract,
                            owner_address=owner_address,
                            gimme=contract_data.get('gimme', False),
                            give_to=contract_data.get('give_to', False),
                            next_balance=contract_data.get('next_balance', False),
                            next_time=contract_data.get('next_time', False),
                            registry_address=contract_data.get('registry_address', '')
                        )

                    elif contract_type.lower() == 'account_index':
                        owner_address = contract_data.get('owner_address', '')
                        if not owner_address:
                            errors.append(f'Contract {i+1}: Account index contract requires owner_address')
                            continue

                        AccountsIndexContract.objects.create(
                            smartcontract_ptr=base_contract,
                            owner_address=owner_address,
                            entry=contract_data.get('entry', False),
                            entry_count=contract_data.get('entry_count', False),
                            is_active=contract_data.get('is_active', False),
                            activate=contract_data.get('activate', False),
                            deactivate=contract_data.get('deactivate', False),
                            add=contract_data.get('add', False),
                            remove=contract_data.get('remove', False)
                        )

                    created_contracts.append({
                        'name': name,
                        'address': address,
                        'contract_type': contract_type,
                        'user': user_name
                    })

                    self.stdout.write(
                        self.style.SUCCESS(
                            f'Created contract "{name}" ({contract_type}) at {address} '
                            f'assigned to user: {user_name}'
                        )
                    )

            except Exception as e:
                errors.append(f'Contract {i+1}: {str(e)}')
                continue

        # Summary
        if dry_run:
            self.stdout.write(
                self.style.WARNING(f'Would create {len(contracts_data)} contracts')
            )
        else:
            self.stdout.write(
                self.style.SUCCESS(f'Successfully created {len(created_contracts)} contracts')
            )

            if created_contracts:
                self.stdout.write('\nCreated contracts:')
                for contract in created_contracts:
                    self.stdout.write(
                        f'  - {contract["name"]} ({contract["contract_type"]}) at {contract["address"]} '
                        f'assigned to {contract["user"]}')

        if errors:
            self.stdout.write('\nErrors:')
            for error in errors:
                self.stdout.write(self.style.ERROR(f'  - {error}'))

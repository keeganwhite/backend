"""
Django command to create RADIUSdesk instances, clouds, realms, and profiles from a JSON file.
"""
import json
import os
import logging
from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth import get_user_model
from radiusdesk.models import (
    RadiusDeskInstance,
    Cloud,
    Realm,
    RadiusDeskProfile
)

User = get_user_model()
logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """Django command to create RADIUSdesk instances, clouds, realms, and profiles from JSON file."""

    help = 'Creates RADIUSdesk instances, clouds, realms, and profiles from JSON file'

    def add_arguments(self, parser):
        """Add command arguments."""
        parser.add_argument(
            'json_file',
            type=str,
            help='Path to JSON file containing RADIUSdesk configuration data'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be created without actually creating anything'
        )

    def validate_instance_data(self, instance_data, index):
        """Validate RADIUSdesk instance data."""
        required_fields = ['name', 'base_url', 'username', 'password']
        missing_fields = [field for field in required_fields if field not in instance_data]

        if missing_fields:
            raise CommandError(
                f'Instance {index+1}: Missing required fields: {", ".join(missing_fields)}'
            )

        # Validate administrators if provided
        administrators = instance_data.get('administrators', [])
        if administrators:
            for admin_username in administrators:
                try:
                    User.objects.get(username=admin_username)
                except User.DoesNotExist:
                    raise CommandError(
                        f'Instance {index+1}: Administrator user "{admin_username}" does not exist'
                    )

    def validate_cloud_data(self, cloud_data, index):
        """Validate cloud data."""
        required_fields = ['name', 'radius_desk_id']
        missing_fields = [field for field in required_fields if field not in cloud_data]

        if missing_fields:
            raise CommandError(
                f'Cloud {index+1}: Missing required fields: {", ".join(missing_fields)}'
            )

    def validate_realm_data(self, realm_data, index):
        """Validate realm data."""
        required_fields = ['name', 'radius_desk_id']
        missing_fields = [field for field in required_fields if field not in realm_data]

        if missing_fields:
            raise CommandError(
                f'Realm {index+1}: Missing required fields: {", ".join(missing_fields)}'
            )

    def validate_profile_data(self, profile_data, index):
        """Validate profile data."""
        required_fields = ['name', 'radius_desk_id']
        missing_fields = [field for field in required_fields if field not in profile_data]

        if missing_fields:
            raise CommandError(
                f'Profile {index+1}: Missing required fields: {", ".join(missing_fields)}'
            )

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
                config_data = json.load(f)
        except json.JSONDecodeError as e:
            raise CommandError(f'Invalid JSON format: {str(e)}')
        except Exception as e:
            raise CommandError(f'Error reading JSON file: {str(e)}')

        # Validate JSON structure
        if not isinstance(config_data, list):
            raise CommandError(
                'JSON file must contain a list of RADIUSdesk instance configurations.'
            )

        if dry_run:
            self.stdout.write(
                self.style.WARNING('DRY RUN MODE - No objects will be created')
            )

        created_objects = []
        errors = []

        for i, instance_config in enumerate(config_data):
            try:
                # Validate instance data
                self.validate_instance_data(instance_config, i)

                instance_name = instance_config['name']
                base_url = instance_config['base_url']
                username = instance_config['username']
                password = instance_config['password']
                accepts_crypto = instance_config.get('accepts_crypto', False)
                administrators = instance_config.get('administrators', [])

                if dry_run:
                    self.stdout.write(f'Would create instance: {instance_name}')
                    created_objects.append({
                        'type': 'instance',
                        'name': instance_name,
                        'status': 'would_create'
                    })
                else:
                    # Create or get RADIUSdesk instance
                    instance, created = RadiusDeskInstance.objects.get_or_create(
                        name=instance_name,
                        defaults={
                            'base_url': base_url,
                            'username': username,
                            'password': password,
                            'accepts_crypto': accepts_crypto,
                        }
                    )

                    if created:
                        self.stdout.write(f'Created RADIUSdesk instance: {instance_name}')
                    else:
                        self.stdout.write(f'RADIUSdesk instance already exists: {instance_name}')

                    # Add administrators
                    for admin_username in administrators:
                        try:
                            admin_user = User.objects.get(username=admin_username)
                            instance.administrators.add(admin_user)
                            self.stdout.write(
                                f'Added administrator {admin_username} to instance {instance_name}'
                            )
                        except User.DoesNotExist:
                            errors.append(
                                f'Instance {instance_name}: Administrator user "{admin_username}" does not exist'
                            )

                # Process clouds
                clouds_data = instance_config.get('clouds', [])
                for j, cloud_data in enumerate(clouds_data):
                    try:
                        self.validate_cloud_data(cloud_data, j)

                        cloud_name = cloud_data['name']
                        cloud_radius_desk_id = cloud_data['radius_desk_id']

                        if dry_run:
                            self.stdout.write(f'Would create cloud: {cloud_name}')
                            created_objects.append({
                                'type': 'cloud',
                                'name': cloud_name,
                                'instance': instance_name,
                                'status': 'would_create'
                            })
                        else:
                            # Create cloud in database
                            cloud, cloud_created = Cloud.objects.get_or_create(
                                name=cloud_name,
                                radius_desk_instance=instance,
                                defaults={'radius_desk_id': cloud_radius_desk_id}
                            )

                            if cloud_created:
                                self.stdout.write(f'Created cloud: {cloud_name}')
                            else:
                                self.stdout.write(f'Cloud already exists: {cloud_name}')

                        # Process realms
                        realms_data = cloud_data.get('realms', [])
                        for k, realm_data in enumerate(realms_data):
                            try:
                                self.validate_realm_data(realm_data, k)

                                realm_name = realm_data['name']
                                realm_radius_desk_id = realm_data['radius_desk_id']

                                if dry_run:
                                    self.stdout.write(f'Would create realm: {realm_name}')
                                    created_objects.append({
                                        'type': 'realm',
                                        'name': realm_name,
                                        'instance': instance_name,
                                        'cloud': cloud_name,
                                        'status': 'would_create'
                                    })
                                else:
                                    # Create realm in database
                                    realm, realm_created = Realm.objects.get_or_create(
                                        name=realm_name,
                                        cloud=cloud,
                                        radius_desk_instance=instance,
                                        defaults={'radius_desk_id': realm_radius_desk_id}
                                    )

                                    if realm_created:
                                        self.stdout.write(f'Created realm: {realm_name}')
                                    else:
                                        self.stdout.write(f'Realm already exists: {realm_name}')

                                # Process profiles
                                profiles_data = realm_data.get('profiles', [])
                                for profile_idx, profile_data in enumerate(profiles_data):
                                    try:
                                        self.validate_profile_data(profile_data, profile_idx)

                                        profile_name = profile_data['name']
                                        profile_radius_desk_id = profile_data['radius_desk_id']

                                        if dry_run:
                                            self.stdout.write(f'Would create profile: {profile_name}')
                                            created_objects.append({
                                                'type': 'profile',
                                                'name': profile_name,
                                                'instance': instance_name,
                                                'cloud': cloud_name,
                                                'realm': realm_name,
                                                'status': 'would_create'
                                            })
                                        else:
                                            # Create profile in database
                                            profile, profile_created = RadiusDeskProfile.objects.get_or_create(
                                                name=profile_name,
                                                realm=realm,
                                                cloud=cloud,
                                                radius_desk_instance=instance,
                                                defaults={
                                                    'radius_desk_id': profile_radius_desk_id,
                                                    'data_limit_enabled': profile_data.get('data_limit_enabled', False),
                                                    'data_limit_gb': profile_data.get('data_limit_gb', 0),
                                                    'data_limit_reset': profile_data.get('data_limit_reset', 'never'),
                                                    'speed_limit_enabled': profile_data.get('speed_limit_enabled', False),
                                                    'speed_limit_mbs': profile_data.get('speed_limit_mbs', 0),
                                                    'limit_session_enabled': profile_data.get('limit_session_enabled', False),
                                                    'session_limit': profile_data.get('session_limit', 0),
                                                    'cost': profile_data.get('cost', 0)
                                                }
                                            )

                                            if profile_created:
                                                self.stdout.write(f'Created profile: {profile_name}')
                                            else:
                                                self.stdout.write(f'Profile already exists: {profile_name}')

                                            created_objects.append({
                                                'type': 'profile',
                                                'name': profile_name,
                                                'instance': instance_name,
                                                'cloud': cloud_name,
                                                'realm': realm_name,
                                                'status': 'created' if profile_created else 'exists'
                                            })

                                    except Exception as e:
                                        errors.append(f'Profile {profile_name}: {str(e)}')

                                if not dry_run:
                                    created_objects.append({
                                        'type': 'realm',
                                        'name': realm_name,
                                        'instance': instance_name,
                                        'cloud': cloud_name,
                                        'status': 'created' if realm_created else 'exists'
                                    })

                            except Exception as e:
                                errors.append(f'Realm {realm_name}: {str(e)}')

                        if not dry_run:
                            created_objects.append({
                                'type': 'cloud',
                                'name': cloud_name,
                                'instance': instance_name,
                                'status': 'created' if cloud_created else 'exists'
                            })

                    except Exception as e:
                        errors.append(f'Cloud {cloud_name}: {str(e)}')

                if not dry_run:
                    created_objects.append({
                        'type': 'instance',
                        'name': instance_name,
                        'status': 'created' if created else 'exists'
                    })

            except Exception as e:
                errors.append(f'Instance {i+1}: {str(e)}')

        # Summary
        self.stdout.write('\n' + '='*50)
        self.stdout.write('SUMMARY')
        self.stdout.write('='*50)

        if created_objects:
            self.stdout.write(f'\nCreated/Found {len(created_objects)} objects:')
            for obj in created_objects:
                status_color = self.style.SUCCESS if obj['status'] == 'created' else self.style.WARNING
                self.stdout.write(
                    status_color(f"  {obj['type'].title()}: {obj['name']} ({obj['status']})")
                )

        if errors:
            self.stdout.write(f'\n{len(errors)} errors occurred:')
            for error in errors:
                self.stdout.write(self.style.ERROR(f"  {error}"))

        if not errors and not dry_run:
            self.stdout.write(self.style.SUCCESS('\nAll RADIUSdesk objects created successfully!'))
        elif dry_run:
            self.stdout.write(self.style.WARNING('\nDry run completed. No objects were created.'))

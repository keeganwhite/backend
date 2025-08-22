"""
Django command to create a superuser using environment variables.
"""
import os
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.conf import settings

User = get_user_model()


class Command(BaseCommand):
    """Django command to create a superuser using environment variables."""
    
    help = 'Creates a superuser using SUPERUSER_USERNAME and SUPERUSER_PASSWORD from .env'

    def handle(self, *args, **options):
        """Entry point for Django management command."""
        # Get credentials from environment variables
        username = os.getenv('SUPERUSER_USERNAME')
        password = os.getenv('SUPERUSER_PASSWORD')
        
        if not username:
            self.stdout.write(
                self.style.ERROR('SUPERUSER_USERNAME not found in environment variables.')
            )
            return
        
        if not password:
            self.stdout.write(
                self.style.ERROR('SUPERUSER_PASSWORD not found in environment variables.')
            )
            return
        
        # Check if superuser already exists
        if User.objects.filter(username=username).exists():
            self.stdout.write(
                self.style.WARNING(f'Superuser with username "{username}" already exists.')
            )
            return
        
        # Create superuser
        try:
            user = User.objects.create_superuser(
                email=f"{username}@inethi.com",
                username=username,
                password=password
            )
            self.stdout.write(
                self.style.SUCCESS(
                    f'Successfully created superuser "{username}" with email "{user.email}"'
                )
            )
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Failed to create superuser: {str(e)}')
            )

#!/usr/bin/env python3
"""
Utility script to generate Django secret key and encryption key for Inethi backend setup.
Run this script to get the keys needed for your .env file.
"""

import sys
from cryptography.fernet import Fernet

def generate_django_secret_key():
    """Generate a Django secret key."""
    try:
        from django.core.management.utils import get_random_secret_key
        return get_random_secret_key()
    except ImportError:
        print("Warning: Django not available, generating a random key instead.")
        import secrets
        import string
        chars = string.ascii_letters + string.digits + "!@#$%^&*(-_=+)"
        return ''.join(secrets.choice(chars) for _ in range(50))

def generate_encryption_key():
    """Generate an encryption key for Fernet."""
    return Fernet.generate_key().decode()

def main():
    print("=" * 60)
    print("🔑 Inethi Backend Key Generator")
    print("=" * 60)
    print()
    
    try:
        # Generate Django secret key
        print("📝 Generating Django Secret Key...")
        django_key = generate_django_secret_key()
        print(f"✅ Django Secret Key:")
        print(f"   {django_key}")
        print()
        
        # Generate encryption key
        print("🔐 Generating Encryption Key...")
        encryption_key = generate_encryption_key()
        print(f"✅ Encryption Key:")
        print(f"   {encryption_key}")
        print()
        
        # Display usage instructions
        print("=" * 60)
        print("📋 Usage Instructions:")
        print("=" * 60)
        print()
        print("Add these keys to your .env file:")
        print()
        print(f"DJANGO_SECRET_KEY={django_key}")
        print(f"ENCRYPTION_KEY={encryption_key}")
        print()
        print("⚠️  Important Security Notes:")
        print("   • Keep these keys secure and never commit them to version control")
        print("   • Use different keys for development and production")
        print("   • Store production keys securely (e.g., environment variables)")
        print()
        print("🎉 Keys generated successfully!")
        
    except Exception as e:
        print(f"❌ Error generating keys: {e}")
        print()
        print("💡 Troubleshooting:")
        print("   • Make sure you have the required packages installed:")
        print("     pip install cryptography django")
        sys.exit(1)

if __name__ == "__main__":
    main()

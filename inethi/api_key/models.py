import secrets
from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()


class APIKey(models.Model):
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="api_keys"
    )
    key = models.CharField(max_length=255, unique=True, blank=True)  # API Key
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        """Generate API key if not already set"""
        if not self.key:
            self.key = self.generate_key()
        super().save(*args, **kwargs)

    def generate_key(self):
        """Generates a unique API key"""
        return secrets.token_urlsafe(32)  # 256-bit random key

    def __str__(self):
        return f"API Key for {self.user.username}"

from rest_framework import serializers
from .models import APIKey


class APIKeySerializer(serializers.ModelSerializer):
    class Meta:
        model = APIKey
        fields = ["id", "created_at", "is_active", "user"]
        read_only_fields = ["created_at", "user"]
        # Explicitly exclude sensitive field: key

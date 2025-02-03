from rest_framework import serializers
from .models import APIKey


class APIKeySerializer(serializers.ModelSerializer):
    class Meta:
        model = APIKey
        fields = ["id", "key", "created_at", "is_active", "user"]
        read_only_fields = ["key", "created_at", "user"]

from django.contrib import admin
from .models import APIKey


@admin.register(APIKey)
class APIKeyAdmin(admin.ModelAdmin):
    list_display = ("user", "key", "is_active", "created_at")
    readonly_fields = ("key", "created_at")  # Prevent manual key editing
    list_filter = ("is_active",)

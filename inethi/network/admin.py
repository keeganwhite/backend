from django.contrib import admin
from .models import Host, Ping, Network


@admin.register(Host)
class HostAdmin(admin.ModelAdmin):
    list_display = (
        'name',
        'ip_address',
        'mac_address',
        'user',
        'radiusdesk_instance'
    )
    search_fields = (
        'ip_address',
        'mac_address',
        'user',
        'radiusdesk_instance'
    )
    list_filter = ('ip_address',)


@admin.register(Ping)
class PingAdmin(admin.ModelAdmin):
    list_display = ('host', 'is_alive', 'timestamp')
    list_filter = ('host', 'is_alive')
    ordering = ('-timestamp',)


@admin.register(Network)
class NetworkAdmin(admin.ModelAdmin):
    list_display = ('name', 'created_by', 'created_at')
    search_fields = ('name', 'created_by__username')
    filter_horizontal = ('admins',)

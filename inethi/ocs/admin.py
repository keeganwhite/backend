from django.contrib import admin
from .models import (
    OCSInstance,
    OCSProductOffering,
    OCSSubscriber,
    DataBundle,
    DataPurchase,
    OCSMapping,
    TopUpHistory
)


@admin.register(OCSInstance)
class OCSInstanceAdmin(admin.ModelAdmin):
    list_display = ['name', 'base_url', 'accepts_crypto', 'verify_ssl', 'is_active']
    list_filter = ['accepts_crypto', 'verify_ssl', 'is_active']
    search_fields = ['name', 'base_url']
    filter_horizontal = ['administrators']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'base_url', 'is_active')
        }),
        ('Authentication', {
            'fields': ('username', 'password'),
            'description': 'OCS server authentication credentials'
        }),
        ('Settings', {
            'fields': ('accepts_crypto', 'verify_ssl')
        }),
        ('Administrators', {
            'fields': ('administrators',),
            'description': 'Users who can manage this OCS instance'
        }),
    )


@admin.register(OCSProductOffering)
class OCSProductOfferingAdmin(admin.ModelAdmin):
    list_display = ['name', 'ocs_instance', 'price', 'data_mb', 'validity_days', 'is_active']
    list_filter = ['is_active', 'ocs_instance', 'validity_days']
    search_fields = ['name', 'description', 'offering_id']
    readonly_fields = ['created_at', 'updated_at']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'ocs_instance', 'offering_id', 'description')
        }),
        ('Pricing & Data', {
            'fields': ('price', 'data_mb', 'validity_days')
        }),
        ('Status', {
            'fields': ('is_active',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(OCSSubscriber)
class OCSSubscriberAdmin(admin.ModelAdmin):
    list_display = ['user', 'ocs_instance', 'imsi', 'phone_number', 'created_at']
    list_filter = ['ocs_instance', 'created_at']
    search_fields = ['user__username', 'user__email', 'imsi', 'phone_number']
    readonly_fields = ['service_id', 'product_id', 'created_at', 'updated_at']
    
    fieldsets = (
        ('User & Instance', {
            'fields': ('user', 'ocs_instance')
        }),
        ('SIM Information', {
            'fields': ('imsi', 'phone_number')
        }),
        ('OCS IDs', {
            'fields': ('service_id', 'product_id'),
            'description': 'IDs from the OCS system'
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(DataBundle)
class DataBundleAdmin(admin.ModelAdmin):
    list_display = ['name', 'ocs_instance', 'product_offering', 'price', 'data_mb', 'payment_method', 'is_active']
    list_filter = ['is_active', 'payment_method', 'ocs_instance']
    search_fields = ['name', 'product_offering__name']
    readonly_fields = ['created_at', 'updated_at']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'ocs_instance', 'product_offering')
        }),
        ('Bundle Details', {
            'fields': ('price', 'data_mb', 'payment_method')
        }),
        ('Status', {
            'fields': ('is_active',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(DataPurchase)
class DataPurchaseAdmin(admin.ModelAdmin):
    list_display = ['user', 'bundle', 'ocs_subscriber', 'payment_method', 'amount_paid', 'status', 'purchase_date']
    list_filter = ['status', 'payment_method', 'purchase_date', 'bundle__ocs_instance']
    search_fields = ['user__username', 'bundle__name', 'ocs_subscriber__imsi']
    readonly_fields = ['purchase_date']
    
    fieldsets = (
        ('Purchase Details', {
            'fields': ('user', 'bundle', 'ocs_subscriber', 'payment_method', 'amount_paid', 'status')
        }),
        ('Transaction', {
            'fields': ('transaction',),
            'description': 'Blockchain transaction (for crypto payments)'
        }),
        ('Timestamps', {
            'fields': ('purchase_date',),
            'classes': ('collapse',)
        }),
    )


@admin.register(OCSMapping)
class OCSMappingAdmin(admin.ModelAdmin):
    list_display = ['user', 'ocs_instance', 'imsi', 'service_id', 'product_id', 'created_at']
    list_filter = ['ocs_instance', 'created_at']
    search_fields = ['user__username', 'imsi', 'service_id', 'product_id']
    readonly_fields = ['created_at', 'updated_at']
    
    fieldsets = (
        ('User & Instance', {
            'fields': ('user', 'ocs_instance')
        }),
        ('SIM Information', {
            'fields': ('imsi',)
        }),
        ('OCS IDs', {
            'fields': ('service_id', 'product_id'),
            'description': 'IDs from the OCS system'
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(TopUpHistory)
class TopUpHistoryAdmin(admin.ModelAdmin):
    list_display = ['mapping', 'bundle', 'amount_bytes', 'status', 'created_at']
    list_filter = ['status', 'created_at', 'bundle__ocs_instance']
    search_fields = ['mapping__imsi', 'bundle__name', 'adjustment_id']
    readonly_fields = ['created_at']
    
    fieldsets = (
        ('Mapping & Bundle', {
            'fields': ('mapping', 'bundle')
        }),
        ('Top-Up Details', {
            'fields': ('amount_bytes', 'adjustment_id', 'status', 'description')
        }),
        ('Timestamps', {
            'fields': ('created_at',),
            'classes': ('collapse',)
        }),
    )
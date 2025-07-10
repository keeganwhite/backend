from django.contrib import admin
from .models import Reward, UptimeRewardTransaction


@admin.register(Reward)
class RewardAdmin(admin.ModelAdmin):
    list_display = (
        'name', 'user', 'reward_type',
        'reward_amount', 'once_off', 'celery_task_id',
        'created_at'
    )
    search_fields = ('user', 'device')
    list_filter = ('device', 'user')
    ordering = ('-created_at',)


@admin.register(UptimeRewardTransaction)
class UptimeRewardTransactionAdmin(admin.ModelAdmin):
    list_display = (
        'reward', 'transaction', 'uptime_seconds',
        'percentage_awarded', 'created_at'
    )

    ordering = ('-created_at',)

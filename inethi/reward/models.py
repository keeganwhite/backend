from django.db import models
from django.conf import settings
from network.models import Host
from core.models import Transaction


class Reward(models.Model):
    """Model to store the base reward setup before payout"""

    REWARD_TYPE_CHOICES = [
        ('uptime', 'Uptime Based'),
        ('custom', 'Custom'),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="rewards"
    )
    device = models.ForeignKey(
        Host,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="rewards"
    )  # Only required for uptime-based rewards
    name = models.CharField(max_length=255, help_text="Reward Name")
    reward_type = models.CharField(
        max_length=20,
        choices=REWARD_TYPE_CHOICES,
        default='uptime'
    )
    reward_amount = models.DecimalField(
        max_digits=20,
        decimal_places=10,
    )

    interval_minutes = models.IntegerField(
        null=True,
        blank=True,
        help_text="Interval for recurring rewards in minutes"
    )

    is_cancelled = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    once_off = models.BooleanField(default=True)
    celery_task_id = models.CharField(
        max_length=255,
        null=True,
        blank=True
    )
    network = models.ForeignKey(
        'network.Network',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="rewards",
        help_text="Network associated with this reward"
    )

    def cancel(self):
        """Cancel a scheduled reward"""
        self.is_cancelled = True
        self.save()


class UptimeRewardTransaction(models.Model):
    """Stores the actual reward payout details"""

    reward = models.ForeignKey(
        Reward,
        on_delete=models.CASCADE,
        related_name="reward_transactions"
    )
    transaction = models.OneToOneField(
        Transaction,
        on_delete=models.CASCADE,
        related_name="reward_transaction"
    )
    uptime_seconds = models.IntegerField(help_text="Total uptime in seconds")
    percentage_awarded = models.DecimalField(
        max_digits=5, decimal_places=2,
        help_text="Percentage of total reward"
    )
    created_at = models.DateTimeField(auto_now_add=True)

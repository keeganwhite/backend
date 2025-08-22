from django.db import models
from django.core.validators import RegexValidator
from django.conf import settings
from timescale.db.models.models import TimescaleModel
from radiusdesk.models import (
    Cloud,
    RadiusDeskInstance,
    Realm,
)

# validator to ensure the MAC address format is correct
mac_address_validator = RegexValidator(
    regex=r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$',
    message="Enter a valid MAC address in format XX:XX:XX:XX:XX:XX."
)


class Network(models.Model):
    name = models.CharField(max_length=255)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="created_networks",
        help_text="User who created this network"
    )
    admins = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        related_name="administered_networks",
        help_text="Users who can administrate this network"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

    class Meta:
        unique_together = (("name", "created_by"),)


class Host(models.Model):
    DEVICE_TYPE_CHOICES = [
        ('unknown', 'Unknown'),
        ('dns_server', 'DNS Server'),
        ('server', 'Server'),
        ('firewall', 'Firewall'),
        ('access_point', 'Access Point'),
        ('switch', 'Switch'),
    ]
    name = models.CharField(
        max_length=200,
        blank=True,
        null=True,
    )
    ip_address = models.GenericIPAddressField(

    )
    mac_address = models.CharField(
        max_length=17,
        blank=True,
        null=True,

        validators=[mac_address_validator],
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="hosts",
        blank=True,
        null=True
    )
    radiusdesk_instance = models.ForeignKey(
        RadiusDeskInstance,
        on_delete=models.CASCADE,
        related_name="hosts",
        blank=True,
        null=True,
    )
    cloud = models.ForeignKey(
        Cloud,
        on_delete=models.CASCADE,
        related_name="hosts",
        blank=True,
        null=True,
    )
    realm = models.ForeignKey(
        Realm,
        on_delete=models.CASCADE,
        related_name="hosts",
        blank=True,
        null=True,
    )
    device_type = models.CharField(
        max_length=20,
        choices=DEVICE_TYPE_CHOICES,
        default='unknown',
        help_text="Select the type of device "
                  "(DNS Server, Server, Firewall, Access Point, Switch)",
    )

    network = models.ForeignKey(
        Network,
        on_delete=models.CASCADE,
        related_name="hosts",
        blank=True,
        null=True
    )

    def __str__(self):
        return self.name if self.name else self.ip_address

    class Meta:
        unique_together = (
            ("network", "ip_address"),
        )


class Ping(TimescaleModel):
    host = models.ForeignKey(
        Host,
        on_delete=models.CASCADE,
        related_name='ping_results'
    )
    is_alive = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)

    network = models.ForeignKey(
        Network,
        on_delete=models.CASCADE,
        related_name='pings',
        blank=True,
        null=True
    )

    def __str__(self):
        status = "Alive" if self.is_alive else "Down"
        return f"{self.host} at {self.timestamp}: {status}"

    class Meta:
        # TimescaleDB requires the time column to be part of the primary key
        unique_together = (('timestamp', 'id'),)

    class TimescaleMeta:
        # Tell TimescaleDB to use 'timestamp' as the time column instead of 'time'
        time_column = 'timestamp'

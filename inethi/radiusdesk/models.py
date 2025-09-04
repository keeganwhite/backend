from django.conf import settings
from django.db import models


class RadiusDeskInstance(models.Model):
    name = models.CharField(max_length=255, unique=True)
    base_url = models.URLField(help_text="Base URL for the RADIUSdesk instance")
    username = models.CharField(max_length=255)
    password = models.CharField(max_length=255)
    token = models.CharField(max_length=255, blank=True, default="")
    # Link admin users to a RadiusDeskInstance
    administrators = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        blank=True,
        related_name="admin_radiusdesk_instances",
        help_text="Users who have network administrator rights for this instance"
    )
    accepts_crypto = models.BooleanField(default=False)

    def __str__(self):
        return self.name


class Cloud(models.Model):
    name = models.CharField(max_length=255)
    radius_desk_instance = models.ForeignKey(
        RadiusDeskInstance,
        on_delete=models.CASCADE,
        related_name="clouds"
    )
    radius_desk_id = models.IntegerField()

    def __str__(self):
        return self.name


class Realm(models.Model):
    name = models.CharField(max_length=255)
    cloud = models.ForeignKey(
        Cloud,
        on_delete=models.CASCADE,
        related_name="realms"
    )
    radius_desk_instance = models.ForeignKey(
        RadiusDeskInstance,
        on_delete=models.CASCADE,
        related_name="realms"
    )
    radius_desk_id = models.IntegerField()

    def __str__(self):
        return self.name


class RadiusDeskProfile(models.Model):
    name = models.CharField(max_length=255)
    realm = models.ForeignKey(
        Realm,
        on_delete=models.CASCADE,
        related_name="profiles"
    )
    cloud = models.ForeignKey(
        Cloud,
        on_delete=models.CASCADE,
        related_name="profiles"
    )
    radius_desk_instance = models.ForeignKey(
        RadiusDeskInstance,
        on_delete=models.CASCADE,
        related_name="profiles"
    )
    radius_desk_id = models.IntegerField()
    data_limit_enabled = models.BooleanField(default=False)
    data_limit_gb = models.FloatField(default=0)
    data_limit_reset = models.CharField(max_length=255, default="never")
    speed_limit_enabled = models.BooleanField(default=False)
    speed_limit_mbs = models.FloatField(default=0)
    limit_session_enabled = models.BooleanField(default=False)
    session_limit = models.IntegerField(default=0)
    cost = models.FloatField(default=0)

    def __str__(self):
        return self.name


class Voucher(models.Model):
    voucher_code = models.CharField(max_length=255)
    realm = models.ForeignKey(
        Realm,
        on_delete=models.CASCADE,
        related_name="vouchers"
    )
    cloud = models.ForeignKey(
        Cloud,
        on_delete=models.CASCADE,
        related_name="vouchers"
    )
    radius_desk_instance = models.ForeignKey(
        RadiusDeskInstance,
        on_delete=models.CASCADE,
        related_name="vouchers"
    )
    profile = models.ForeignKey(
        RadiusDeskProfile,
        on_delete=models.CASCADE,
        related_name="vouchers",
        blank=True,
        null=True,
        help_text="The specific profile used to create this voucher"
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="vouchers",
        blank=True,
        null=True
    )
    wallet_address = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.voucher_code

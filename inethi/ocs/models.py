from django.conf import settings
from django.db import models


class OCSInstance(models.Model):
    name = models.CharField(max_length=255, unique=True)
    base_url = models.URLField(help_text="Base URL for the OCS instance")
    username = models.CharField(max_length=255)
    password = models.CharField(max_length=255)
    verify_ssl = models.BooleanField(default=False, help_text="Whether to verify SSL certificates")
    # Link admin users to an OCSInstance
    administrators = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        blank=True,
        related_name="admin_ocs_instances",
        help_text="Users who have network administrator rights for this instance"
    )
    accepts_crypto = models.BooleanField(default=False)
    is_active = models.BooleanField(
        default=True,
        help_text="Whether this OCS instance is active and accepting new subscribers"
    )

    def __str__(self):
        return self.name


class OCSProductOffering(models.Model):
    name = models.CharField(max_length=255, help_text="Offering name (e.g., 'Data (1G)')")
    ocs_instance = models.ForeignKey(
        OCSInstance,
        on_delete=models.CASCADE,
        related_name="product_offerings",
        help_text="The OCS instance this offering belongs to"
    )
    offering_id = models.CharField(
        max_length=255,
        help_text="ID of the offering in the OCS system"
    )
    description = models.TextField(blank=True, help_text="Description of the offering")
    price = models.FloatField(help_text="Cost for the offering")
    data_mb = models.IntegerField(help_text="Data amount in megabytes")
    validity_days = models.IntegerField(
        default=30,
        help_text="How many days the data is valid"
    )
    is_active = models.BooleanField(default=True, help_text="Whether this offering is currently available")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "OCS Product Offering"
        verbose_name_plural = "OCS Product Offerings"
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} - {self.ocs_instance.name}"


class OCSSubscriber(models.Model):
    """
    Junction table linking Users to OCSInstances.
    Stores the OCS service and product IDs for each user-instance pair.
    """
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="ocs_subscribers",
        help_text="The application user"
    )
    ocs_instance = models.ForeignKey(
        OCSInstance,
        on_delete=models.CASCADE,
        related_name="ocs_subscribers",
        help_text="The OCS instance this subscriber belongs to"
    )
    imsi = models.CharField(
        max_length=15,
        help_text="SIM card IMSI (15 digits)"
    )
    phone_number = models.CharField(
        max_length=20,
        help_text="Phone number in international format"
    )
    service_id = models.CharField(
        max_length=255,
        help_text="The service ID from OCS API"
    )
    product_id = models.CharField(
        max_length=255,
        help_text="The product subscription ID from OCS API"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('user', 'ocs_instance')  # One registration per user per instance
        verbose_name = "OCS Subscriber"
        verbose_name_plural = "OCS Subscribers"

    def __str__(self):
        return f"{self.user.username} @ {self.ocs_instance.name} ({self.imsi})"


class DataBundle(models.Model):
    """
    Data bundle that can be purchased for an OCS subscriber.
    """
    PAYMENT_METHOD_CHOICES = [
        ('crypto', 'Cryptocurrency'),
        ('1foryou', '1FourYou'),
        ('other', 'Other'),
    ]

    name = models.CharField(
        max_length=255,
        help_text="Bundle name (e.g., '5GB Data Bundle')"
    )
    ocs_instance = models.ForeignKey(
        OCSInstance,
        on_delete=models.CASCADE,
        related_name="data_bundles",
        help_text="The OCS instance this bundle is for"
    )
    product_offering = models.ForeignKey(
        OCSProductOffering,
        on_delete=models.CASCADE,
        related_name="data_bundles",
        help_text="The product offering this bundle is based on"
    )
    price = models.FloatField(
        help_text="Bundle cost"
    )
    payment_method = models.CharField(
        max_length=20,
        choices=PAYMENT_METHOD_CHOICES,
        help_text="Payment method accepted for this bundle"
    )
    data_mb = models.IntegerField(
        help_text="Data amount in megabytes"
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Whether this bundle is currently available for purchase"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Data Bundle"
        verbose_name_plural = "Data Bundles"
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} ({self.data_mb}MB) - {self.ocs_instance.name}"


class DataPurchase(models.Model):
    """
    Record of a data bundle purchase by a user.
    """
    STATUS_CHOICES = [
        ('success', 'Success'),
        ('failed', 'Failed'),
        ('pending', 'Pending'),
    ]

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="data_purchases",
        help_text="The user who purchased the bundle"
    )
    bundle = models.ForeignKey(
        DataBundle,
        on_delete=models.CASCADE,
        related_name="purchases",
        help_text="The bundle that was purchased"
    )
    ocs_subscriber = models.ForeignKey(
        OCSSubscriber,
        on_delete=models.CASCADE,
        related_name="data_purchases",
        help_text="The OCS subscriber account"
    )
    transaction = models.ForeignKey(
        'core.Transaction',
        on_delete=models.SET_NULL,
        related_name="data_purchases",
        null=True,
        blank=True,
        help_text="The blockchain transaction (for crypto payments)"
    )
    payment_method = models.CharField(
        max_length=20,
        help_text="Payment method used"
    )
    amount_paid = models.FloatField(
        help_text="Amount paid for the bundle"
    )
    purchase_date = models.DateTimeField(
        auto_now_add=True,
        help_text="Date and time of purchase"
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='pending',
        help_text="Status of the purchase"
    )

    class Meta:
        verbose_name = "Data Purchase"
        verbose_name_plural = "Data Purchases"
        ordering = ['-purchase_date']

    def __str__(self):
        return f"{self.user.username} - {self.bundle.name} - {self.status}"


class OCSMapping(models.Model):
    """Slim mapping for resolving top-ups by IMSI per user and OCS instance."""
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="ocs_mappings",
    )
    ocs_instance = models.ForeignKey(
        OCSInstance,
        on_delete=models.CASCADE,
        related_name="ocs_mappings",
    )
    imsi = models.CharField(max_length=16)
    service_id = models.CharField(max_length=255)
    product_id = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("user", "ocs_instance", "imsi")
        indexes = [
            models.Index(fields=["user", "ocs_instance", "imsi"]),
            models.Index(fields=["product_id"]),
        ]

    def __str__(self):
        return f"{self.user_id}/{self.ocs_instance_id}/{self.imsi} -> {self.product_id}"


class TopUpHistory(models.Model):
    """Track top-ups made via the simplified top-up endpoint."""
    STATUS_CHOICES = [
        ('success', 'Success'),
        ('failed', 'Failed'),
    ]

    mapping = models.ForeignKey(
        OCSMapping,
        on_delete=models.CASCADE,
        related_name="top_ups",
        help_text="The OCS mapping this top-up was applied to"
    )
    bundle = models.ForeignKey(
        DataBundle,
        on_delete=models.CASCADE,
        related_name="top_ups",
        help_text="The data bundle that was used for this top-up"
    )
    amount_bytes = models.BigIntegerField(help_text="Amount added in bytes")
    adjustment_id = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="OCS adjustment ID from the API response"
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='success',
        help_text="Status of the top-up"
    )
    description = models.CharField(
        max_length=255,
        blank=True,
        help_text="Description for the top-up"
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Top-Up History"
        verbose_name_plural = "Top-Up Histories"
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=["mapping", "-created_at"]),
        ]

    def __str__(self):
        return f"{self.mapping.imsi} - {self.bundle.name} - {self.status}"
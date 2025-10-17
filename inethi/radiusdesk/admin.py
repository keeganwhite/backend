from django.contrib import admin
from .models import (
    RadiusDeskInstance,
    Cloud,
    Realm,
    RadiusDeskProfile,
    Voucher,
    RadiusDeskUser,
    InternetBundle,
    BundlePurchase
)

admin.site.register(RadiusDeskInstance)
admin.site.register(Cloud)
admin.site.register(Realm)
admin.site.register(RadiusDeskProfile)
admin.site.register(Voucher)
admin.site.register(RadiusDeskUser)
admin.site.register(InternetBundle)
admin.site.register(BundlePurchase)

"""
URL Configuration for radiusdesk API
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    RadiusDeskInstanceViewSet,
    PublicRadiusDeskInstanceViewSet,
    CloudViewSet,
    RealmViewSet,
    RadiusDeskProfileViewSet,
    VoucherViewSet,
    RadiusDeskUserViewSet,
    NetworkAdminVoucherViewSet,
    InternetBundleViewSet,
    BundlePurchaseViewSet
)

app_name = 'radiusdesk'

router = DefaultRouter()
router.register(r'radiusdesk-instances', RadiusDeskInstanceViewSet)
router.register(r'public/radiusdesk-instances', PublicRadiusDeskInstanceViewSet, basename='public-radiusdesk-instances')
router.register(r'clouds', CloudViewSet)
router.register(r'realms', RealmViewSet)
router.register(r'profiles', RadiusDeskProfileViewSet)
router.register(r'vouchers', VoucherViewSet)
router.register(r'radiusdesk-users', RadiusDeskUserViewSet, basename='radiusdesk-users')
router.register(
    r'network-admin/vouchers',
    NetworkAdminVoucherViewSet,
    basename='network-admin-vouchers'
)
router.register(r'internet-bundles', InternetBundleViewSet)
router.register(r'bundle-purchases', BundlePurchaseViewSet)

urlpatterns = [
    path('', include(router.urls)),
]

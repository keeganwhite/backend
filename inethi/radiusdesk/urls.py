"""
URL Configuration for radiusdesk API
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    RadiusDeskInstanceViewSet,
    CloudViewSet,
    RealmViewSet,
    RadiusDeskProfileViewSet,
    VoucherViewSet,
    NetworkAdminVoucherViewSet
)

app_name = 'radiusdesk'

router = DefaultRouter()
router.register(r'radiusdesk-instances', RadiusDeskInstanceViewSet)
router.register(r'clouds', CloudViewSet)
router.register(r'realms', RealmViewSet)
router.register(r'profiles', RadiusDeskProfileViewSet)
router.register(r'vouchers', VoucherViewSet)
router.register(
    r'network-admin/vouchers',
    NetworkAdminVoucherViewSet,
    basename='network-admin-vouchers'
)

urlpatterns = [
    path('', include(router.urls)),
]

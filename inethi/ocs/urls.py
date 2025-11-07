"""
URL Configuration for OCS API
Includes both simplified endpoints and full CRUD endpoints
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    OCSInstanceViewSet,
    PublicOCSInstanceViewSet,
    OCSProductOfferingViewSet,
    OCSSubscriberViewSet,
    DataBundleViewSet,
    DataPurchaseViewSet,
    OnboardView,
    TopupView
)

app_name = 'ocs'

router = DefaultRouter()
router.register(r'ocs-instances', OCSInstanceViewSet)
router.register(r'public/ocs-instances', PublicOCSInstanceViewSet, basename='public-ocs-instances')
router.register(r'ocs-offerings', OCSProductOfferingViewSet)
router.register(r'ocs-subscribers', OCSSubscriberViewSet, basename='ocs-subscribers')
router.register(r'data-bundles', DataBundleViewSet)
router.register(r'data-purchases', DataPurchaseViewSet)

urlpatterns = [
    path('', include(router.urls)),
    # Simplified endpoints
    path('ocs/onboard', OnboardView.as_view(), name='onboard'),
    path('ocs/topup', TopupView.as_view(), name='topup'),
]

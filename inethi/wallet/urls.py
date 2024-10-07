from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import WalletViewSet

app_name = 'wallet'

# Register the WalletViewSet with the router
router = DefaultRouter()
router.register('wallet', WalletViewSet, basename='wallet')

urlpatterns = [
    # Include the automatically generated routes from the router
    path('', include(router.urls)),
]

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import TransactionViewSet

app_name = 'transaction'

router = DefaultRouter()
router.register('transaction', TransactionViewSet, basename='transaction')

urlpatterns = [
    path('', include(router.urls)),
]

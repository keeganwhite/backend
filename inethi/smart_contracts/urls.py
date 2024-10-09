from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import SmartContractViewSet

app_name = 'smartcontract'

router = DefaultRouter()
router.register('contract', SmartContractViewSet, basename='smartcontract')

urlpatterns = [
    path('', include(router.urls)),
]

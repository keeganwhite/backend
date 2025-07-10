from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import RewardViewSet, UptimeRewardTransactionViewSet

app_name = 'reward'

router = DefaultRouter()
router.register(r'rewards', RewardViewSet)
router.register(r'uptime-transactions', UptimeRewardTransactionViewSet)

urlpatterns = [
    path('', include(router.urls)),
]

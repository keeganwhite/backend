from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    HostViewSet,
    PingViewSet,
    NetworkViewSet,
    ingest_uptime_data,
    aggregate_ping_view,
    aggregate_uptime_view,
    device_uptime_line_view,
    update_host_by_identifier,
    delete_host_by_identifier
)

app_name = 'network'

router = DefaultRouter()
router.register(r'hosts', HostViewSet)
router.register(r'pings', PingViewSet)
router.register(r'networks', NetworkViewSet)

urlpatterns = [
    path(
        'hosts/update-by-identifier/',
        update_host_by_identifier,
        name='update-host-by-identifier'
    ),
    path(
        'hosts/delete-by-identifier/',
        delete_host_by_identifier,
        name='update-host-by-identifier'
    ),
    path(
        'ingest-uptime/',
        ingest_uptime_data,
        name='ingest-uptime'
    ),
    path(
        'ping-aggregates/',
        aggregate_ping_view,
        name='ping-aggregates'
    ),
    path(
        'network/up-time/',
        aggregate_uptime_view,
        name='up-time-aggregate'
    ),
    path(
        'network/device-uptime/',
        device_uptime_line_view,
        name='device-uptime-line'
    ),
    path('', include(router.urls)),
]

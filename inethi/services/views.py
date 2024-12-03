from rest_framework.viewsets import ModelViewSet
from rest_framework.permissions import IsAuthenticated
from core.models import Service
from .serializers import ServiceSerializer
from utils.keycloak import KeycloakAuthentication
from utils.superuser_or_read_only_permission import IsSuperUserOrReadOnly


class ServiceViewSet(ModelViewSet):
    """
    ViewSet for managing Service model.
    """
    authentication_classes = [KeycloakAuthentication]
    permission_classes = [IsAuthenticated, IsSuperUserOrReadOnly]
    queryset = Service.objects.all()
    serializer_class = ServiceSerializer

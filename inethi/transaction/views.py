from rest_framework.permissions import IsAuthenticated
from rest_framework.viewsets import ReadOnlyModelViewSet
from core.models import Transaction
from .serializers import TransactionSerializer
from rest_framework.decorators import action
from rest_framework.response import Response

from utils.keycloak import KeycloakAuthentication


class TransactionViewSet(ReadOnlyModelViewSet):
    queryset = Transaction.objects.all()
    serializer_class = TransactionSerializer
    authentication_classes = [KeycloakAuthentication]
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        if self.request.user.is_superuser:
            return super().get_queryset()
        return Transaction.objects.filter(
            sender=self.request.user
        ) | Transaction.objects.filter(
            recipient=self.request.user
        )

    @action(detail=False, methods=['get'], url_path='by-user')
    def list_by_user(self, request):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

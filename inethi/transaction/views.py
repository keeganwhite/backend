from rest_framework.permissions import IsAuthenticated
from rest_framework.viewsets import ReadOnlyModelViewSet
from rest_framework.pagination import PageNumberPagination
from core.models import Transaction
from .serializers import TransactionSerializer
from rest_framework.decorators import action
from rest_framework.response import Response

from utils.keycloak import KeycloakAuthentication


class TransactionPagination(PageNumberPagination):
    """Custom pagination for transaction endpoints."""
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100


class TransactionViewSet(ReadOnlyModelViewSet):
    queryset = Transaction.objects.all()
    serializer_class = TransactionSerializer
    authentication_classes = [KeycloakAuthentication]
    permission_classes = [IsAuthenticated]
    pagination_class = TransactionPagination

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
        queryset = self.get_queryset().order_by('-timestamp')
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

"""
Filters for user views
"""
from django.contrib.auth import get_user_model
from django_filters import rest_framework as filters
from django.db.models import Q


class UserFilter(filters.FilterSet):
    """Filter for user queryset"""
    has_imsi = filters.BooleanFilter(method='filter_has_imsi')
    has_wallet = filters.BooleanFilter(method='filter_has_wallet')
    search = filters.CharFilter(method='filter_search')

    class Meta:
        model = get_user_model()
        fields = ['is_active', 'is_staff', 'is_superuser']

    def filter_has_imsi(self, queryset, name, value):
        """Filter users by whether they have an IMSI"""
        if value:
            return queryset.exclude(imsi__isnull=True).exclude(imsi='')
        else:
            return queryset.filter(Q(imsi__isnull=True) | Q(imsi=''))

    def filter_has_wallet(self, queryset, name, value):
        """Filter users by whether they have a wallet"""
        if value:
            return queryset.filter(wallet__isnull=False).distinct()
        else:
            return queryset.filter(wallet__isnull=True)

    def filter_search(self, queryset, name, value):
        """Search users by username, email, first_name, or last_name"""
        return queryset.filter(
            Q(username__icontains=value) |
            Q(email__icontains=value) |
            Q(first_name__icontains=value) |
            Q(last_name__icontains=value)
        )


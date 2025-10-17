
from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.pagination import PageNumberPagination
import logging
from decimal import Decimal

from .models import (
    RadiusDeskInstance,
    Cloud,
    Realm,
    RadiusDeskProfile,
    Voucher,
    RadiusDeskUser
)
from .serializers import (
    RadiusDeskInstanceSerializer,
    PublicRadiusDeskInstanceSerializer,
    CloudSerializer,
    RealmSerializer,
    RadiusDeskProfileSerializer,
    VoucherSerializer,
    RadiusDeskUserSerializer,
    CreateRadiusDeskUserSerializer,
    AddDataTopUpSerializer
)
from utils.radiusdesk_client import RadiusDeskClientManager
from radiusdesk_api.exceptions import APIError, AuthenticationError
from utils.keycloak import KeycloakAuthentication
from utils.super_user_or_api_key import IsSuperUserOrAPIKeyUser
from utils.super_user_or_api_key_or_network_admin import (
    IsSuperUserOrAPIKeyUserOrNetworkAdmin
)
from utils.keycloak_or_api_key import KeycloakOrAPIKeyAuthentication

from core.models import User
from core.models import Transaction

logger = logging.getLogger(__name__)


class VoucherPagination(PageNumberPagination):
    """Custom pagination for voucher endpoints."""
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100


class RadiusDeskInstanceViewSet(viewsets.ModelViewSet):
    queryset = RadiusDeskInstance.objects.all()
    serializer_class = RadiusDeskInstanceSerializer
    authentication_classes = [KeycloakAuthentication]
    permission_classes = [IsSuperUserOrAPIKeyUserOrNetworkAdmin]

    def get_queryset(self):
        user = self.request.user
        # If the user is a superuser or does not have the network admin permission,
        # allow access to all instances.
        if user.is_superuser or not user.has_perm('core.network_admin'):
            return RadiusDeskInstance.objects.all()
        # Otherwise, filter to only those instances the network admin is associated with.
        return RadiusDeskInstance.objects.filter(administrators=user)

    @action(
        detail=False,
        methods=['get'],
        permission_classes=[IsAuthenticated],
        url_path="crypto-instances-profiles"
    )
    def crypto_instances_profiles(self, request):
        """
        Returns a list of RadiusDeskInstances that accept crypto payments,
        along with their associated profiles that have a cost greater than zero.
        """
        # Get all instances that accept crypto
        instances = RadiusDeskInstance.objects.filter(accepts_crypto=True)
        print(instances)

        results = []
        for instance in instances:
            # Filter profiles for this instance where cost > 0
            profiles = RadiusDeskProfile.objects.filter(
                radius_desk_instance=instance,
                cost__gt=0
            )
            instance_data = RadiusDeskInstanceSerializer(instance).data
            instance_data["profiles"] = RadiusDeskProfileSerializer(
                profiles, many=True).data
            results.append(instance_data)
        return Response(results, status=status.HTTP_200_OK)


class PublicRadiusDeskInstanceViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Public read-only viewset for RadiusDeskInstance.
    Returns only non-sensitive information (id, name, accepts_crypto).
    No authentication required.
    """
    queryset = RadiusDeskInstance.objects.all()
    serializer_class = PublicRadiusDeskInstanceSerializer
    permission_classes = [AllowAny]
    authentication_classes = []


class CloudViewSet(viewsets.ModelViewSet):
    queryset = Cloud.objects.all()
    serializer_class = CloudSerializer
    authentication_classes = [KeycloakAuthentication]
    permission_classes = [IsSuperUserOrAPIKeyUserOrNetworkAdmin]

    def get_queryset(self):
        user = self.request.user
        radius_instance_id = self.request.query_params.get("radius_instance")
        if user.is_superuser or not user.has_perm('core.network_admin'):
            qs = self.queryset
        else:
            # Filter Clouds whose related RadiusDeskInstance
            # includes the user as an administrator.
            qs = self.queryset.filter(radius_desk_instance__administrators=user)
        if radius_instance_id:
            qs = qs.filter(radius_desk_instance_id=radius_instance_id)
        return qs


class RealmViewSet(viewsets.ModelViewSet):
    queryset = Realm.objects.all()
    serializer_class = RealmSerializer
    authentication_classes = [KeycloakAuthentication]
    permission_classes = [IsSuperUserOrAPIKeyUserOrNetworkAdmin]

    def get_queryset(self):
        user = self.request.user
        cloud_id = self.request.query_params.get("cloud")
        radius_instance_id = self.request.query_params.get("radius_instance")

        # ilter to Realms whose associated RadiusDeskInstance includes them.
        if user.is_superuser or not user.has_perm('core.network_admin'):
            qs = self.queryset
        else:
            qs = self.queryset.filter(radius_desk_instance__administrators=user)

        if cloud_id:
            qs = qs.filter(cloud_id=cloud_id)
        if radius_instance_id:
            qs = qs.filter(radius_desk_instance_id=radius_instance_id)
        return qs


class RadiusDeskProfileViewSet(viewsets.ModelViewSet):
    queryset = RadiusDeskProfile.objects.all()
    serializer_class = RadiusDeskProfileSerializer
    authentication_classes = [KeycloakAuthentication]
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """Filter Profiles by Realm, Cloud, and/or RadiusDeskInstance."""
        realm_id = self.request.query_params.get("realm")
        cloud_id = self.request.query_params.get("cloud")
        radius_instance_id = self.request.query_params.get("radius_instance")
        queryset = self.queryset
        if realm_id:
            queryset = queryset.filter(realm_id=realm_id)
        if cloud_id:
            queryset = queryset.filter(cloud_id=cloud_id)
        if radius_instance_id:
            queryset = queryset.filter(
                radius_desk_instance_id=radius_instance_id
            )
        return queryset


class VoucherViewSet(viewsets.ModelViewSet):
    queryset = Voucher.objects.all()
    serializer_class = VoucherSerializer
    authentication_classes = [KeycloakOrAPIKeyAuthentication]
    permission_classes = [IsAuthenticated]
    pagination_class = VoucherPagination

    @action(detail=False, methods=['get'])
    def voucher_stats(self, request):
        """
        Retrieve summary statistics for a single voucher using its voucher_code.
        Uses the radaccts endpoint to get session data and returns a manageable summary.

        Requires:
         - voucher_code (string)
         - radius_desk_instance_pk (primary key)
         - radius_desk_cloud_pk (primary key)

        Returns:
         - voucher_code: The voucher code
         - status: "used" if voucher has been used, "unused" if not used yet
         - message: Additional message (only for unused vouchers)
         - most_recent_stop_time: Most recent session stop time (null if unused)
         - total_data_used_gb: Total data used in GB (0 if unused)
         - total_time_connected_hours: Total connection time in hours (0 if unused)
         - total_sessions: Number of sessions (0 if unused)
         - total_data_bytes: Total data used in bytes (raw, 0 if unused)
         - total_time_seconds: Total connection time in seconds (raw, 0 if unused)
        """
        voucher_code = request.query_params.get("voucher_code")
        radius_desk_instance_pk = request.query_params.get("radius_desk_instance_pk")
        radius_desk_cloud_pk = request.query_params.get("radius_desk_cloud_pk")

        logger.info(f"Fetching voucher stats for voucher_code: {voucher_code}")

        if not voucher_code or not radius_desk_instance_pk or not radius_desk_cloud_pk:
            return Response(
                {"error": "voucher_code, radius_desk_instance_pk, and radius_desk_cloud_pk are required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Retrieve the instance and cloud objects
            instance = RadiusDeskInstance.objects.get(pk=radius_desk_instance_pk)
            cloud_obj = Cloud.objects.get(pk=radius_desk_cloud_pk)

            # Get the RadiusDesk client
            client = RadiusDeskClientManager.get_client(instance)

            # Fetch specific voucher details using the radaccts endpoint
            voucher_stats_response = client.vouchers.get_details(
                voucher_code=voucher_code,
                limit=150
            )

            # Check if voucher was found
            if not voucher_stats_response.get("success", False):
                return Response(
                    {"error": "Failed to fetch voucher data from RADIUSdesk."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            items = voucher_stats_response.get("items", [])
            if not items:
                # Voucher exists but hasn't been used yet
                return Response(
                    {
                        "voucher_code": voucher_code,
                        "status": "unused",
                        "message": "Voucher has not been used yet.",
                        "most_recent_stop_time": None,
                        "total_data_used_gb": 0,
                        "total_time_connected_hours": 0,
                        "total_sessions": 0,
                        "total_data_bytes": 0,
                        "total_time_seconds": 0
                    },
                    status=status.HTTP_200_OK
                )

            # Process the data to get manageable summary
            meta_data = voucher_stats_response.get("metaData", {})

            # Find the most recent stop time and check for active sessions
            most_recent_stop_time = None

            if items:
                print('items', items)

                # Check if any sessions are currently active
                active_sessions = [item for item in items if item.get("active") is True]
                if active_sessions:
                    most_recent_stop_time = "User is currently online"
                else:
                    # Only process inactive sessions with valid timestamps
                    inactive_items = []
                    for item in items:
                        acctstoptime = item.get("acctstoptime")
                        # Only include items with valid timestamp strings (not integers)
                        if acctstoptime and isinstance(acctstoptime, str):
                            inactive_items.append(item)

                    if inactive_items:
                        # Sort by acctstoptime to find the most recent
                        sorted_items = sorted(
                            inactive_items,
                            key=lambda x: x.get("acctstoptime", ""),
                            reverse=True
                        )
                        if sorted_items:
                            most_recent_stop_time = sorted_items[0].get("acctstoptime")
                    else:
                        most_recent_stop_time = "Unknown"

                print('most_recent_stop_time', most_recent_stop_time)

            # Get total data used (in bytes, convert to GB for readability)
            total_data_bytes = int(meta_data.get("totalInOut", 0))
            total_data_gb = round(total_data_bytes / (1024 * 1024 * 1024), 2)

            # Get total time connected (sum of all session times in seconds, convert to hours)
            total_time_seconds = sum(int(item.get("acctsessiontime", 0)) for item in items)
            total_time_hours = round(total_time_seconds / 3600, 2)

            # Return manageable summary data
            summary_data = {
                "voucher_code": voucher_code,
                "status": "used",
                "most_recent_stop_time": most_recent_stop_time,
                "total_data_used_gb": total_data_gb,
                "total_time_connected_hours": total_time_hours,
                "total_sessions": len(items),
                "total_data_bytes": total_data_bytes,
                "total_time_seconds": total_time_seconds
            }

            return Response(summary_data, status=status.HTTP_200_OK)

        except AuthenticationError as e:
            logger.error(f"Authentication error fetching voucher stats: {str(e)}")
            return Response(
                {"error": f"Authentication failed: {str(e)}"},
                status=status.HTTP_401_UNAUTHORIZED
            )
        except APIError as e:
            logger.error(f"API error fetching voucher stats: {str(e)}")
            return Response(
                {"error": f"RadiusDesk API error: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Error fetching voucher stats: {str(e)}")
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['get'])
    def user_vouchers(self, request):
        """
        Retrieve vouchers for the authenticated user,
        ordered by the latest first with pagination.
        """
        user = request.user
        vouchers = Voucher.objects.filter(user=user).order_by('-created_at')

        # Use pagination
        paginator = VoucherPagination()
        page = paginator.paginate_queryset(vouchers, request)
        serializer = self.get_serializer(page, many=True)
        for voucher in serializer.data:
            logger.info(f"Voucher: {voucher}")
        return paginator.get_paginated_response(serializer.data)

    @action(
        detail=False,
        methods=['get'],
        permission_classes=[IsSuperUserOrAPIKeyUserOrNetworkAdmin]
    )
    def search_vouchers(self, request):
        """
        Search vouchers by wallet_address or username with pagination.
        At least one of these parameters must be provided.
        """

        radius_desk_instance_pk = request.query_params.get(
            'radius_desk_instance_pk'
        )
        radius_desk_cloud_pk = request.query_params.get(
            'radius_desk_cloud_pk'
        )

        if not radius_desk_instance_pk or not radius_desk_cloud_pk:
            return Response(
                {
                    "error":
                        "Missing required parameters: "
                        "radius_desk_instance_pk and radius_desk_cloud_pk"
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        radius_desk_instance_db = RadiusDeskInstance.objects.get(
            pk=radius_desk_instance_pk
        )
        # network admin(not a superuser), ensure they're associated
        if request.user.has_perm('core.network_admin') and not request.user.is_superuser:
            if not radius_desk_instance_db.administrators.filter(
                    pk=request.user.pk).exists():
                return Response(
                    {"error": "Unauthorized to access this RadiusDeskInstance."},
                    status=status.HTTP_403_FORBIDDEN
                )

        wallet_address = request.query_params.get("wallet_address")
        username = request.query_params.get("username")

        if not wallet_address and not username:
            return Response(
                {"error": "Either wallet_address or username is required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Start with a base queryset and apply filters efficiently
        vouchers = Voucher.objects.filter(
            radius_desk_instance=radius_desk_instance_pk,
            cloud=radius_desk_cloud_pk
        )

        if wallet_address:
            vouchers = vouchers.filter(wallet_address__icontains=wallet_address)
        if username:
            vouchers = vouchers.filter(user__username__icontains=username)

        vouchers = vouchers.order_by('-created_at')

        # Use pagination
        paginator = VoucherPagination()
        page = paginator.paginate_queryset(vouchers, request)
        serializer = self.get_serializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)

    @action(
        detail=False,
        methods=['post'],
        permission_classes=[IsSuperUserOrAPIKeyUserOrNetworkAdmin]
    )
    def add_voucher(self, request):
        user = request.user
        user_db = User.objects.get(username=user)
        radius_desk_instance_pk = request.data.get('radius_desk_instance_pk')
        radius_desk_profile_pk = request.data.get('radius_desk_profile_pk')
        radius_desk_cloud_pk = request.data.get('radius_desk_cloud_pk')
        radius_desk_realm_pk = request.data.get('radius_desk_realm_pk')
        if request.data.get('quantity'):
            quantity = request.data.get('quantity')
        else:
            quantity = 1

        try:
            radius_desk_instance_db = RadiusDeskInstance.objects.get(
                pk=radius_desk_instance_pk
            )
        except RadiusDeskInstance.DoesNotExist:
            return Response(
                {"error": "RadiusDeskInstance not found."},
                status=status.HTTP_404_NOT_FOUND
            )
        # If network admin (and not a superuser), verify they're associated.
        if (request.user.has_perm('core.network_admin')
                and not request.user.is_superuser):
            if not radius_desk_instance_db.administrators.filter(
                    pk=request.user.pk).exists():
                return Response(
                    {"error": "Unauthorized for this RadiusDeskInstance."},
                    status=status.HTTP_403_FORBIDDEN
                )
        radius_desk_token = radius_desk_instance_db.token
        radius_desk_base_url = radius_desk_instance_db.base_url
        radius_desk_cloud_db = Cloud.objects.get(pk=radius_desk_cloud_pk)
        radius_desk_profile_db = RadiusDeskProfile.objects.get(
            pk=radius_desk_profile_pk
        )
        radius_desk_realm_db = Realm.objects.get(pk=radius_desk_realm_pk)

        try:
            # Get the RadiusDesk client
            client = RadiusDeskClientManager.get_client(radius_desk_instance_db)

            # **Transaction Logic (Optional)**
            sender_address = request.data.get('sender_address')
            recipient_address = request.data.get('recipient_address')
            amount = request.data.get('amount')
            category = request.data.get('category', 'INTERNET_COUPON')
            token = request.data.get('token')

            voucher_response = client.vouchers.create(
                realm_id=radius_desk_realm_db.radius_desk_id,
                profile_id=radius_desk_profile_db.radius_desk_id,
                quantity=quantity,
            )

            # Handle single vs multiple vouchers
            if quantity == 1:
                # Single voucher - voucher_response is a dict with 'name' key
                voucher_codes = [voucher_response['name']]
            else:
                # Multiple vouchers - voucher_response is a list of dicts
                voucher_codes = [voucher['name'] for voucher in voucher_response]

            created_vouchers = []

            if sender_address and recipient_address and amount and token:
                Transaction.objects.create(
                    recipient_address=recipient_address,
                    sender_address=sender_address,
                    amount=Decimal(amount),
                    category=category,
                    token=token
                )

                # Create a voucher record for each voucher code
                for voucher_code in voucher_codes:
                    voucher_obj = Voucher.objects.create(
                        voucher_code=voucher_code,
                        realm=radius_desk_realm_db,
                        cloud=radius_desk_cloud_db,
                        radius_desk_instance=radius_desk_instance_db,
                        profile=radius_desk_profile_db,
                        wallet_address=sender_address,
                    )
                    created_vouchers.append(voucher_obj)
            else:
                # Create a voucher record for each voucher code
                for voucher_code in voucher_codes:
                    voucher_obj = Voucher.objects.create(
                        voucher_code=voucher_code,
                        realm=radius_desk_realm_db,
                        cloud=radius_desk_cloud_db,
                        radius_desk_instance=radius_desk_instance_db,
                        profile=radius_desk_profile_db,
                        user=user_db
                    )
                    created_vouchers.append(voucher_obj)

            # Return appropriate response based on quantity
            if quantity == 1:
                return Response(
                    {'voucher': voucher_codes[0]},
                    status=status.HTTP_201_CREATED
                )
            else:
                return Response(
                    {'vouchers': voucher_codes, 'count': len(voucher_codes)},
                    status=status.HTTP_201_CREATED
                )

        except AuthenticationError as e:
            logger.error(f"Authentication error adding voucher: {str(e)}")
            return Response(
                {"error": f"Authentication failed: {str(e)}"},
                status=status.HTTP_401_UNAUTHORIZED
            )
        except APIError as e:
            logger.error(f"API error adding voucher: {str(e)}")
            return Response(
                {"error": f"RadiusDesk API error: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Error adding voucher: {str(e)}")
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(detail=False,
            methods=['get'],
            permission_classes=[IsSuperUserOrAPIKeyUser]
            )
    def wallet_address_vouchers(self, request):
        wallet_address = request.query_params.get("wallet_address")
        if not wallet_address:
            return Response(
                {"error": "Wallet address is required"},
                status=status.HTTP_400_BAD_REQUEST
            )
        try:
            vouchers = Voucher.objects.filter(
                wallet_address=wallet_address
            ).order_by('-created_at')

            # Use pagination
            paginator = VoucherPagination()
            page = paginator.paginate_queryset(vouchers, request)
            serializer = self.get_serializer(page, many=True)
            return paginator.get_paginated_response(serializer.data)
        except Exception as e:
            return Response({
                "error": f"unexpected error {e}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(
        detail=False,
        methods=['get'],
        permission_classes=[IsSuperUserOrAPIKeyUserOrNetworkAdmin]
    )
    def get_all_vouchers_stats(self, request):
        """
        Get all vouchers statistics from RadiusDesk instance
        :param request:
        :return: a list of all vouchers and their statistics
        """
        try:
            radius_desk_instance_pk = request.query_params.get(
                'radius_desk_instance_pk'
            )
            radius_desk_cloud_pk = request.query_params.get(
                'radius_desk_cloud_pk'
            )
            limit = request.query_params.get('limit', 50)

            if not radius_desk_instance_pk or not radius_desk_cloud_pk:
                return Response(
                    {
                        "error":
                            "Missing required parameters: "
                            "radius_desk_instance_pk and radius_desk_cloud_pk"
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            radius_desk_instance_db = RadiusDeskInstance.objects.get(
                pk=radius_desk_instance_pk
            )
            # If network admin (and not a superuser), ensure they're associated
            if (request.user.has_perm('core.network_admin')
                    and not request.user.is_superuser):
                if not radius_desk_instance_db.administrators.filter(
                    pk=request.user.pk
                ).exists():
                    return Response(
                        {"error": "Unauthorized for this RadiusDeskInstance."},
                        status=status.HTTP_403_FORBIDDEN
                    )

            # Get the RadiusDesk client
            client = RadiusDeskClientManager.get_client(radius_desk_instance_db)

            voucher_stats = client.vouchers.list(limit=limit)

            filtered_vouchers = [
                {
                    "voucher_code": voucher.get("name"),
                    "perc_time_used": voucher.get("perc_time_used"),
                    "perc_data_used": voucher.get("perc_data_used"),
                    "last_accept_time": voucher.get(
                        "last_accept_time_in_words"
                    ),
                    "cloud_id": voucher.get("cloud_id"),
                    "realm_id": voucher.get("realm_id"),
                    "profile_id": voucher.get("profile_id"),
                }
                for voucher in voucher_stats.get("items", [])
            ]

            return Response(
                {"vouchers": filtered_vouchers},
                status=status.HTTP_200_OK
            )

        except AuthenticationError as e:
            logger.error(f"Authentication error getting voucher stats: {str(e)}")
            return Response(
                {"error": f"Authentication failed: {str(e)}"},
                status=status.HTTP_401_UNAUTHORIZED
            )
        except APIError as e:
            logger.error(f"API error getting voucher stats: {str(e)}")
            return Response(
                {"error": f"RadiusDesk API error: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Error getting voucher stats: {str(e)}")
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(
        detail=False,
        methods=['get'],
        permission_classes=[IsSuperUserOrAPIKeyUserOrNetworkAdmin]
    )
    def get_all_vouchers_stats_db(self, request):
        """
        Get all vouchers statistics from database with pagination.
        This is the main method for getting voucher stats now.
        """
        try:
            radius_desk_instance_pk = request.query_params.get(
                'radius_desk_instance_pk'
            )
            radius_desk_cloud_pk = request.query_params.get(
                'radius_desk_cloud_pk'
            )

            if not radius_desk_instance_pk or not radius_desk_cloud_pk:
                return Response(
                    {
                        "error":
                            "Missing required parameters: "
                            "radius_desk_instance_pk and radius_desk_cloud_pk"
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            radius_desk_instance_db = RadiusDeskInstance.objects.get(
                pk=radius_desk_instance_pk
            )
            # If network admin (and not a superuser), ensure they're associated
            if (request.user.has_perm('core.network_admin')
                    and not request.user.is_superuser):
                if not radius_desk_instance_db.administrators.filter(
                    pk=request.user.pk
                ).exists():
                    return Response(
                        {"error": "Unauthorized for this RadiusDeskInstance."},
                        status=status.HTTP_403_FORBIDDEN
                    )

            # Get vouchers from database with pagination
            vouchers = Voucher.objects.filter(
                radius_desk_instance=radius_desk_instance_pk,
                cloud=radius_desk_cloud_pk
            ).order_by('-created_at')

            # Use pagination
            paginator = VoucherPagination()
            page = paginator.paginate_queryset(vouchers, request)
            serializer = self.get_serializer(page, many=True)
            logger.info(f"Vouchers: {serializer.data}")
            return paginator.get_paginated_response(serializer.data)

        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(
        detail=False,
        methods=['get'],
        permission_classes=[IsSuperUserOrAPIKeyUserOrNetworkAdmin]
    )
    def get_voucher_stats_detailed(self, request):
        """
        Get detailed statistics for a specific voucher using the radaccts endpoint.
        This provides comprehensive usage data including data transfer, session times, etc.
        """
        voucher_code = request.query_params.get("voucher_code")
        radius_desk_instance_pk = request.query_params.get("radius_desk_instance_pk")
        radius_desk_cloud_pk = request.query_params.get("radius_desk_cloud_pk")

        if not voucher_code or not radius_desk_instance_pk or not radius_desk_cloud_pk:
            return Response(
                {"error": "voucher_code, radius_desk_instance_pk, and radius_desk_cloud_pk are required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Get voucher from database
            voucher = Voucher.objects.filter(
                voucher_code=voucher_code,
                radius_desk_instance=radius_desk_instance_pk,
                cloud=radius_desk_cloud_pk
            ).first()

            if not voucher:
                return Response(
                    {"error": "Voucher not found in database."},
                    status=status.HTTP_404_NOT_FOUND
                )

            # Get RADIUSdesk instance and cloud
            instance = RadiusDeskInstance.objects.get(pk=radius_desk_instance_pk)
            cloud_obj = Cloud.objects.get(pk=radius_desk_cloud_pk)

            # Get the RadiusDesk client
            client = RadiusDeskClientManager.get_client(instance)

            # Fetch detailed stats from RADIUSdesk API
            voucher_stats_response = client.vouchers.get_details(
                voucher_code=voucher_code
            )

            # Get profile information
            profile = voucher.realm.profiles.filter(
                radius_desk_instance=instance
            ).first()

            # Calculate usage percentage if profile has data limits
            usage_percentage = None
            if profile and profile.data_limit_enabled and profile.data_limit_gb > 0:
                total_data_bytes = voucher_stats_response.get('metaData', {}).get('totalInOut')
                if total_data_bytes and total_data_bytes != 'null':
                    total_data_gb = float(total_data_bytes) / (1024 * 1024 * 1024)
                    usage_percentage = (total_data_gb / profile.data_limit_gb) * 100

            # Prepare response data
            response_data = {
                "voucher_code": voucher_code,
                "profile_name": profile.name if profile else None,
                "data_limit_gb": profile.data_limit_gb if profile else None,
                "data_limit_enabled": profile.data_limit_enabled if profile else False,
                "usage_percentage": round(usage_percentage, 2) if usage_percentage else None,
                "total_sessions": voucher_stats_response.get('metaData', {}).get('totalCount', 0),
                "total_data_in": voucher_stats_response.get('metaData', {}).get('totalIn'),
                "total_data_out": voucher_stats_response.get('metaData', {}).get('totalOut'),
                "total_data_inout": voucher_stats_response.get('metaData', {}).get('totalInOut'),
                "sessions": voucher_stats_response.get('items', [])
            }

            return Response(response_data, status=status.HTTP_200_OK)

        except AuthenticationError as e:
            logger.error(f"Authentication error getting detailed voucher stats: {str(e)}")
            return Response(
                {"error": f"Authentication failed: {str(e)}"},
                status=status.HTTP_401_UNAUTHORIZED
            )
        except APIError as e:
            logger.error(f"API error getting detailed voucher stats: {str(e)}")
            return Response(
                {"error": f"RadiusDesk API error: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Error getting detailed voucher stats: {str(e)}")
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class RadiusDeskUserViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing RadiusDesk permanent users.
    Allows users to create permanent users in RadiusDesk instances and manage their data top-ups.
    """
    serializer_class = RadiusDeskUserSerializer
    authentication_classes = [KeycloakOrAPIKeyAuthentication]
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """Return only the authenticated user's RadiusDesk users."""
        return RadiusDeskUser.objects.filter(user=self.request.user).select_related(
            'radius_desk_instance', 'profile', 'user'
        )

    @action(detail=False, methods=['post'], url_path='create-permanent-user')
    def create_permanent_user(self, request):
        """
        Create a permanent user in a RadiusDesk instance for the authenticated user.
        
        Expects:
          - radius_desk_instance_pk: PK of the RadiusDeskInstance
          - profile_pk: PK of the RadiusDeskProfile to assign
          - password: Password for the permanent user
          - username (optional): Username (auto-generated if not provided)
          - name, surname, email, phone (optional): User details
        """
        serializer = CreateRadiusDeskUserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        radius_desk_instance_pk = serializer.validated_data['radius_desk_instance_pk']
        profile_pk = serializer.validated_data['profile_pk']
        password = serializer.validated_data['password']
        username = serializer.validated_data.get('username', '')
        name = serializer.validated_data.get('name', '')
        surname = serializer.validated_data.get('surname', '')
        email = serializer.validated_data.get('email', '')
        phone = serializer.validated_data.get('phone', '')

        try:
            # Get the RadiusDesk instance and profile
            instance = RadiusDeskInstance.objects.get(pk=radius_desk_instance_pk)
            profile = RadiusDeskProfile.objects.get(pk=profile_pk)

            # Check if user already has an account in this instance
            if RadiusDeskUser.objects.filter(
                user=request.user,
                radius_desk_instance=instance
            ).exists():
                return Response(
                    {"error": "You already have a permanent user in this RadiusDesk instance."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Auto-generate username if not provided
            if not username:
                username = f"{request.user.username}@{profile.realm.name}".lower()

            # Get the RadiusDesk client
            client = RadiusDeskClientManager.get_client(instance)

            # Create permanent user in RadiusDesk
            user_response = client.users.create(
                username=username,
                password=password,
                realm_id=profile.realm.radius_desk_id,
                profile_id=profile.radius_desk_id,
                name=name or request.user.first_name or '',
                surname=surname or request.user.last_name or '',
                email=email or request.user.email or '',
                phone=phone or ''
            )

            logger.info(f"Created permanent user in RadiusDesk: {user_response}")

            # Create RadiusDeskUser record
            radiusdesk_user = RadiusDeskUser.objects.create(
                user=request.user,
                radius_desk_instance=instance,
                username=username,
                password=password,
                radiusdesk_id=user_response['id'],
                profile=profile
            )

            response_serializer = RadiusDeskUserSerializer(radiusdesk_user)
            return Response(
                response_serializer.data,
                status=status.HTTP_201_CREATED
            )

        except RadiusDeskInstance.DoesNotExist:
            return Response(
                {"error": "RadiusDesk instance not found."},
                status=status.HTTP_404_NOT_FOUND
            )
        except RadiusDeskProfile.DoesNotExist:
            return Response(
                {"error": "RadiusDesk profile not found."},
                status=status.HTTP_404_NOT_FOUND
            )
        except AuthenticationError as e:
            logger.error(f"Authentication error creating permanent user: {str(e)}")
            return Response(
                {"error": f"Authentication failed: {str(e)}"},
                status=status.HTTP_401_UNAUTHORIZED
            )
        except APIError as e:
            logger.error(f"API error creating permanent user: {str(e)}")
            return Response(
                {"error": f"RadiusDesk API error: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Error creating permanent user: {str(e)}")
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(detail=True, methods=['post'], url_path='add-data')
    def add_data(self, request, pk=None):
        """
        Add data top-up to a permanent user.
        
        Expects:
          - amount: Amount of data to add
          - unit: Unit (mb or gb)
          - comment (optional): Comment for the top-up
        """
        radiusdesk_user = self.get_object()

        serializer = AddDataTopUpSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        amount = serializer.validated_data['amount']
        unit = serializer.validated_data['unit']
        comment = serializer.validated_data.get('comment', '')

        try:
            # Get the RadiusDesk client
            client = RadiusDeskClientManager.get_client(
                radiusdesk_user.radius_desk_instance
            )

            # Add data top-up
            top_up_response = client.users.add_data(
                user_id=radiusdesk_user.radiusdesk_id,
                amount=amount,
                unit=unit,
                comment=comment
            )

            logger.info(
                f"Added {amount}{unit} data to user {radiusdesk_user.username}: "
                f"{top_up_response}"
            )

            return Response(
                {
                    "success": True,
                    "message": f"Successfully added {amount}{unit} to {radiusdesk_user.username}",
                    "radiusdesk_response": top_up_response
                },
                status=status.HTTP_200_OK
            )

        except AuthenticationError as e:
            logger.error(f"Authentication error adding data top-up: {str(e)}")
            return Response(
                {"error": f"Authentication failed: {str(e)}"},
                status=status.HTTP_401_UNAUTHORIZED
            )
        except APIError as e:
            logger.error(f"API error adding data top-up: {str(e)}")
            return Response(
                {"error": f"RadiusDesk API error: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Error adding data top-up: {str(e)}")
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(detail=True, methods=['post'], url_path='add-time')
    def add_time(self, request, pk=None):
        """
        Add time top-up to a permanent user.
        
        Expects:
          - amount: Amount of time to add
          - unit: Unit (minutes, hours, or days)
          - comment (optional): Comment for the top-up
        """
        radiusdesk_user = self.get_object()

        # Reuse the data serializer but with different unit choices
        data = request.data.copy()
        amount = data.get('amount')
        unit = data.get('unit', 'minutes')
        comment = data.get('comment', '')

        if not amount:
            return Response(
                {"error": "Amount is required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        if unit not in ['minutes', 'hours', 'days']:
            return Response(
                {"error": "Unit must be one of: minutes, hours, days"},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Get the RadiusDesk client
            client = RadiusDeskClientManager.get_client(
                radiusdesk_user.radius_desk_instance
            )

            # Add time top-up
            top_up_response = client.users.add_time(
                user_id=radiusdesk_user.radiusdesk_id,
                amount=int(amount),
                unit=unit,
                comment=comment
            )

            logger.info(
                f"Added {amount} {unit} to user {radiusdesk_user.username}: "
                f"{top_up_response}"
            )

            return Response(
                {
                    "success": True,
                    "message": f"Successfully added {amount} {unit} to {radiusdesk_user.username}",
                    "radiusdesk_response": top_up_response
                },
                status=status.HTTP_200_OK
            )

        except AuthenticationError as e:
            logger.error(f"Authentication error adding time top-up: {str(e)}")
            return Response(
                {"error": f"Authentication failed: {str(e)}"},
                status=status.HTTP_401_UNAUTHORIZED
            )
        except APIError as e:
            logger.error(f"API error adding time top-up: {str(e)}")
            return Response(
                {"error": f"RadiusDesk API error: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f"Error adding time top-up: {str(e)}")
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )


class NetworkAdminVoucherViewSet(viewsets.ReadOnlyModelViewSet):
    """
    This viewset allows network administrators to view vouchers
    only for those RadiusDeskInstances where they have administrator rights.
    """
    serializer_class = VoucherSerializer
    authentication_classes = [KeycloakOrAPIKeyAuthentication]
    permission_classes = [IsAuthenticated]
    queryset = Voucher.objects.all()
    pagination_class = VoucherPagination

    def get_queryset(self):
        user = self.request.user
        # Return vouchers only for instances where the user is an admin.
        return Voucher.objects.filter(radius_desk_instance__administrators=user).order_by('-created_at')

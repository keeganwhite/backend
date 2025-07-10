
from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated

from decimal import Decimal

from .models import (
    RadiusDeskInstance,
    Cloud,
    Realm,
    RadiusDeskProfile,
    Voucher
)
from .serializers import (
    RadiusDeskInstanceSerializer,
    CloudSerializer,
    RealmSerializer,
    RadiusDeskProfileSerializer,
    VoucherSerializer,
)
from utils.radius_desk import (
    check_token,
    login,
    create_voucher,
    fetch_vouchers
)
from utils.keycloak import KeycloakAuthentication
from utils.super_user_or_api_key import IsSuperUserOrAPIKeyUser
from utils.super_user_or_api_key_or_network_admin import (
    IsSuperUserOrAPIKeyUserOrNetworkAdmin
)
from utils.keycloak_or_api_key import KeycloakOrAPIKeyAuthentication

from core.models import User
from core.models import Transaction


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

    @action(detail=False, methods=['get'])
    def voucher_stats(self, request):
        """
        Retrieve statistics for a single voucher using its voucher_code.
        Requires:
         - voucher_code (string)
         - radius_desk_instance_pk (primary key)
         - radius_desk_cloud_pk (primary key)
        """
        voucher_code = request.query_params.get("voucher_code")
        radius_desk_instance_pk = request.query_params.get("radius_desk_instance_pk")
        radius_desk_cloud_pk = request.query_params.get("radius_desk_cloud_pk")
        print('checking voucher_code', voucher_code)
        if not voucher_code or not radius_desk_instance_pk or not radius_desk_cloud_pk:
            return Response(
                {"error": "voucher_code, radius desk, radius desk cloud required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Retrieve the instance and cloud objects
            instance = RadiusDeskInstance.objects.get(pk=radius_desk_instance_pk)
            cloud_obj = Cloud.objects.get(pk=radius_desk_cloud_pk)

            # Validate or refresh the token if necessary
            token_valid = check_token(instance.token, instance.base_url)
            if not token_valid:
                instance.token = login(
                    username=instance.username,
                    password=instance.password,
                    base_url=instance.base_url
                )
                instance.save()

            # Fetch all vouchers stats from the external service
            voucher_stats_response = fetch_vouchers(
                token=instance.token,
                cloud_id=cloud_obj.radius_desk_id,
                base_url=instance.base_url,
                limit=50000  # Adjust the limit as needed
            )

            # Filter for the voucher with the provided voucher_code.
            # Adjust the key if your fetch_vouchers returns the voucher
            # code under a different key.
            voucher_data = next(
                (v for v in voucher_stats_response.get("items", [])
                    if v.get("name") == voucher_code),
                None
            )

            if not voucher_data:
                return Response(
                    {"error": "Voucher not found."},
                    status=status.HTTP_404_NOT_FOUND
                )

            # Prepare the stats you want to send back
            filtered_stats = {
                "voucher_code": voucher_data.get("name"),
                "perc_time_used": voucher_data.get("perc_time_used"),
                "perc_data_used": voucher_data.get("perc_data_used"),
                "last_accept_time": voucher_data.get("last_accept_time_in_words"),
                # Include additional stats if available...
            }

            return Response(filtered_stats, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['get'])
    def user_vouchers(self, request):
        """
        Retrieve vouchers for the authenticated user,
        ordered by the latest first.
        """
        user = request.user
        vouchers = (Voucher.objects.filter(user=user)
                    .order_by('-created_at')
                    )  # Order by created_at descending
        serializer = self.get_serializer(vouchers, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(
        detail=False,
        methods=['get'],
        permission_classes=[IsSuperUserOrAPIKeyUserOrNetworkAdmin]
    )
    def search_vouchers(self, request):
        """
        Search vouchers by wallet_address or username.
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

        vouchers = Voucher.objects.all()

        if wallet_address:
            vouchers = vouchers.filter(
                wallet_address__icontains=wallet_address,
                radius_desk_instance=radius_desk_instance_pk,
                cloud=radius_desk_cloud_pk
            )
        if username:
            vouchers = vouchers.filter(
                user__username__icontains=username,
                radius_desk_instance=radius_desk_instance_pk,
                cloud=radius_desk_cloud_pk
            )

        vouchers = vouchers.order_by('-created_at')
        serializer = self.get_serializer(vouchers, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

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
            if not radius_desk_token:
                print('token not found')
                token_valid = False
            else:
                token_valid = check_token(
                    radius_desk_token,
                    radius_desk_base_url
                )
            if not token_valid:
                print('token not valid')
                radius_desk_token = login(
                    username=radius_desk_instance_db.username,
                    password=radius_desk_instance_db.password,
                    base_url=radius_desk_base_url
                )
            radius_desk_instance_db.token = radius_desk_token
            radius_desk_instance_db.save()

            # **Transaction Logic (Optional)**
            sender_address = request.data.get('sender_address')
            recipient_address = request.data.get('recipient_address')
            amount = request.data.get('amount')
            category = request.data.get('category', 'INTERNET_COUPON')
            token = request.data.get('token')

            voucher = create_voucher(
                token=radius_desk_token,
                base_url=radius_desk_base_url,
                cloud_id=radius_desk_cloud_db.radius_desk_id,
                realm_id=radius_desk_realm_db.radius_desk_id,
                profile_id=radius_desk_profile_db.radius_desk_id,
                quantity=quantity,
            )

            if sender_address and recipient_address and amount and token:
                Transaction.objects.create(
                    recipient_address=recipient_address,
                    sender_address=sender_address,
                    amount=Decimal(amount),
                    category=category,
                    token=token
                )
                Voucher.objects.create(
                    voucher_code=voucher,
                    realm=radius_desk_realm_db,
                    cloud=radius_desk_cloud_db,
                    radius_desk_instance=radius_desk_instance_db,
                    wallet_address=sender_address,
                )
            else:
                Voucher.objects.create(
                    voucher_code=voucher,
                    realm=radius_desk_realm_db,
                    cloud=radius_desk_cloud_db,
                    radius_desk_instance=radius_desk_instance_db,
                    user=user_db
                )

            return Response(
                {'voucher': voucher},
                status=status.HTTP_201_CREATED
            )

        except Exception as e:
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
            vouchers = (Voucher.objects.filter(
                wallet_address=wallet_address)
                        .order_by('-created_at'))
            serializer = self.get_serializer(vouchers, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
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

            radius_desk_token = radius_desk_instance_db.token
            radius_desk_base_url = radius_desk_instance_db.base_url
            radius_desk_cloud_db = Cloud.objects.get(pk=radius_desk_cloud_pk)
            token_valid = check_token(
                radius_desk_token,
                radius_desk_base_url
            )
            if not token_valid:
                radius_desk_token = login(
                    username=radius_desk_instance_db.username,
                    password=radius_desk_instance_db.password,
                    base_url=radius_desk_base_url
                )
                radius_desk_instance_db.token = radius_desk_token
                radius_desk_instance_db.save()

            voucher_stats = fetch_vouchers(
                token=radius_desk_token,
                cloud_id=radius_desk_cloud_db.radius_desk_id,
                base_url=radius_desk_base_url,
                limit=limit
            )

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

        except Exception as e:
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

    def get_queryset(self):
        user = self.request.user
        # Return vouchers only for instances where the user is an admin.
        return Voucher.objects.filter(radius_desk_instance__administrators=user)

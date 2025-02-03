
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
from utils.radius_desk import check_token, login, create_voucher
from utils.keycloak import KeycloakAuthentication
from utils.super_user_or_api_key import IsSuperUserOrAPIKeyUser
from utils.keycloak_or_api_key import KeycloakOrAPIKeyAuthentication

from core.models import User
from core.models import Transaction  # Import the Transaction model


class RadiusDeskInstanceViewSet(viewsets.ModelViewSet):
    queryset = RadiusDeskInstance.objects.all()
    serializer_class = RadiusDeskInstanceSerializer
    authentication_classes = [KeycloakAuthentication]
    permission_classes = [IsSuperUserOrAPIKeyUser]


class CloudViewSet(viewsets.ModelViewSet):
    queryset = Cloud.objects.all()
    serializer_class = CloudSerializer
    authentication_classes = [KeycloakAuthentication]
    permission_classes = [IsSuperUserOrAPIKeyUser]

    def get_queryset(self):
        """Filter Clouds by RadiusDeskInstance if provided."""
        radius_instance_id = self.request.query_params.get("radius_instance")
        if radius_instance_id:
            return self.queryset.filter(
                radius_desk_instance_id=radius_instance_id
            )
        return self.queryset


class RealmViewSet(viewsets.ModelViewSet):
    queryset = Realm.objects.all()
    serializer_class = RealmSerializer
    authentication_classes = [KeycloakAuthentication]
    permission_classes = [IsSuperUserOrAPIKeyUser]

    def get_queryset(self):
        """Filter Realms by Cloud and optionally by RadiusDeskInstance."""
        cloud_id = self.request.query_params.get("cloud")
        radius_instance_id = self.request.query_params.get("radius_instance")
        queryset = self.queryset
        if cloud_id:
            queryset = queryset.filter(cloud_id=cloud_id)
        if radius_instance_id:
            queryset = queryset.filter(
                radius_desk_instance_id=radius_instance_id
            )
        return queryset


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
        methods=['post'],
        permission_classes=[IsSuperUserOrAPIKeyUser]
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

        radius_desk_instance_db = RadiusDeskInstance.objects.get(
            pk=radius_desk_instance_pk
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
            methods=['post'],
            permission_classes=[IsSuperUserOrAPIKeyUser]
            )
    def wallet_address_vouchers(self, request):
        wallet_address = request.data.get('wallet_address')
        vouchers = (Voucher.objects.filter(
            wallet_address=wallet_address)
                    .order_by('-created_at'))
        serializer = self.get_serializer(vouchers, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

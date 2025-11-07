from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.pagination import PageNumberPagination
import logging
from decimal import Decimal
import httpx

from .models import (
    OCSInstance,
    OCSProductOffering,
    OCSSubscriber,
    OCSMapping,
    DataBundle,
    DataPurchase,
    TopUpHistory
)
from .serializers import (
    OCSInstanceSerializer,
    PublicOCSInstanceSerializer,
    OCSProductOfferingSerializer,
    OCSSubscriberSerializer,
    CreateOCSSubscriberSerializer,
    DataBundleSerializer,
    DataPurchaseSerializer,
    TopUpBalanceSerializer,
    SyncOfferingsSerializer,
    OnboardRequestSerializer,
    TopupRequestSerializer,
    TopUpHistorySerializer
)
from utils.ocs_client import OCSAPIClient, OCSClientManager
from utils.keycloak import KeycloakAuthentication
from utils.super_user_or_api_key import IsSuperUserOrAPIKeyUser
from utils.super_user_or_api_key_or_network_admin import (
    IsSuperUserOrAPIKeyUserOrNetworkAdmin
)
from utils.keycloak_or_api_key import KeycloakOrAPIKeyAuthentication
from utils.crypto import CryptoUtils, decrypt_private_key
from utils.oneforyou_client import OneForYouClient
from django.conf import settings

from core.models import User, Transaction, Wallet
from sigscale_ocs import ServiceInventory, ProductInventory, BalanceManagement

# Create a single instance of OneForYouClient to reuse across requests
oneforyou_client = OneForYouClient()

logger = logging.getLogger(__name__)


def normalize_oneforyou_pin(pin):
    """
    Normalize 1FourYou PIN by removing spaces, hyphens, and other formatting.
    
    Args:
        pin (str): The PIN in any format (e.g., "1206 35846491 0847" or "1206-35846491-0847")
        
    Returns:
        str: Normalized PIN with only digits (e.g., "1206358464910847")
    """
    if not pin:
        return pin
    # Remove spaces, hyphens, and any other non-digit characters
    normalized = ''.join(char for char in str(pin) if char.isdigit())
    return normalized


class OCSInstanceViewSet(viewsets.ModelViewSet):
    queryset = OCSInstance.objects.all()
    serializer_class = OCSInstanceSerializer
    authentication_classes = [KeycloakAuthentication]
    permission_classes = [IsSuperUserOrAPIKeyUserOrNetworkAdmin]

    def get_queryset(self):
        user = self.request.user
        # If the user is a superuser or does not have the network admin permission,
        # allow access to all instances.
        if user.is_superuser or not user.has_perm('core.network_admin'):
            return OCSInstance.objects.all()
        # Otherwise, filter to only those instances the network admin is associated with.
        return OCSInstance.objects.filter(administrators=user)

    @action(
        detail=False,
        methods=['get'],
        permission_classes=[IsAuthenticated],
        url_path="crypto-instances-offerings"
    )
    def crypto_instances_offerings(self, request):
        """
        Returns a list of OCSInstances that accept crypto payments,
        along with their associated product offerings.
        """
        # Get all instances that accept crypto
        instances = OCSInstance.objects.filter(accepts_crypto=True)

        results = []
        for instance in instances:
            # Filter offerings for this instance
            offerings = OCSProductOffering.objects.filter(
                ocs_instance=instance,
                is_active=True
            )
            instance_data = OCSInstanceSerializer(instance).data
            instance_data["offerings"] = OCSProductOfferingSerializer(
                offerings, many=True).data
            results.append(instance_data)
        return Response(results, status=status.HTTP_200_OK)

    @action(
        detail=True,
        methods=['post'],
        permission_classes=[IsSuperUserOrAPIKeyUserOrNetworkAdmin],
        url_path="sync-offerings"
    )
    def sync_offerings(self, request, pk=None):
        """
        Sync product offerings from the OCS server.
        """
        ocs_instance = self.get_object()
        serializer = SyncOfferingsSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        overwrite_existing = serializer.validated_data.get('overwrite_existing', False)
        
        try:
            ocs_client = OCSAPIClient(ocs_instance)
            offerings_result = ocs_client.list_product_offerings()
            
            if not offerings_result['success']:
                return Response(
                    {"error": f"Failed to fetch offerings from OCS: {offerings_result['error']}"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            
            synced_count = 0
            for offering_data in offerings_result['offerings']:
                offering_id = offering_data.get('id')
                if not offering_id:
                    continue
                
                # Check if offering already exists
                existing_offering = OCSProductOffering.objects.filter(
                    ocs_instance=ocs_instance,
                    offering_id=offering_id
                ).first()
                
                if existing_offering and not overwrite_existing:
                    continue
                
                # Create or update offering
                offering_data_dict = {
                    'name': offering_data.get('name', f'Offering {offering_id}'),
                    'description': offering_data.get('description', ''),
                    'price': float(offering_data.get('price', 0)),
                    'data_mb': int(offering_data.get('data_mb', 0)),
                    'validity_days': int(offering_data.get('validity_days', 30)),
                    'is_active': True
                }
                
                if existing_offering:
                    for key, value in offering_data_dict.items():
                        setattr(existing_offering, key, value)
                    existing_offering.save()
                else:
                    OCSProductOffering.objects.create(
                        ocs_instance=ocs_instance,
                        offering_id=offering_id,
                        **offering_data_dict
                    )
                
                synced_count += 1
            
            return Response(
                {
                    "message": f"Successfully synced {synced_count} offerings from OCS server",
                    "synced_count": synced_count
                },
                status=status.HTTP_200_OK
            )
            
        except Exception as e:
            logger.error(f"Error syncing offerings: {str(e)}")
            return Response(
                {"error": f"Failed to sync offerings: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class PublicOCSInstanceViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Public read-only viewset for OCSInstance.
    Returns only non-sensitive information (id, name, accepts_crypto).
    No authentication required.
    """
    queryset = OCSInstance.objects.filter(is_active=True)
    serializer_class = PublicOCSInstanceSerializer
    permission_classes = [AllowAny]
    authentication_classes = []

    @action(detail=True, methods=['get'], url_path='offerings')
    def get_offerings(self, request, pk=None):
        """
        Get all active product offerings for a specific OCS instance.
        """
        try:
            instance = self.get_object()
            offerings = OCSProductOffering.objects.filter(
                ocs_instance=instance,
                is_active=True
            )
            
            offerings_data = []
            for offering in offerings:
                offerings_data.append({
                    'id': offering.offering_id,  # Use the OCS offering_id, not Django id
                    'django_id': offering.id,   # Keep Django id for reference
                    'name': offering.name,
                    'description': offering.description,
                    'data_mb': offering.data_mb,
                    'price': offering.price,
                    'is_active': offering.is_active
                })
            
            return Response({
                'instance': {
                    'id': instance.id,
                    'name': instance.name,
                    'base_url': instance.base_url,
                    'accepts_crypto': instance.accepts_crypto
                },
                'offerings': offerings_data,
                'total_offerings': len(offerings_data)
            }, status=status.HTTP_200_OK)
            
        except OCSInstance.DoesNotExist:
            return Response(
                {"error": "OCS instance not found"},
                status=status.HTTP_404_NOT_FOUND
            )


class OCSProductOfferingViewSet(viewsets.ModelViewSet):
    queryset = OCSProductOffering.objects.all()
    serializer_class = OCSProductOfferingSerializer
    authentication_classes = [KeycloakAuthentication]
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """Filter Offerings by OCS instance."""
        ocs_instance_id = self.request.query_params.get("ocs_instance")
        queryset = self.queryset
        if ocs_instance_id:
            queryset = queryset.filter(ocs_instance_id=ocs_instance_id)
        return queryset.filter(is_active=True)


class OCSSubscriberViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing OCS subscribers.
    Allows users to create OCS subscribers and manage their data top-ups.
    """
    serializer_class = OCSSubscriberSerializer
    authentication_classes = [KeycloakOrAPIKeyAuthentication]
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """Return only the authenticated user's OCS subscribers."""
        return OCSSubscriber.objects.filter(user=self.request.user).select_related(
            'ocs_instance', 'user'
        )

    @action(detail=False, methods=['post'], url_path='create-subscriber')
    def create_subscriber(self, request):
        """
        Create an OCS subscriber for the authenticated user.
        
        Expects:
          - ocs_instance_pk: PK of the OCSInstance
          - imsi: SIM card IMSI (15 digits)
          - phone_number: Phone number in international format
          - offering_id: Product offering ID to subscribe to
          - initial_balance_cents: Initial balance in cents (optional)
        """
        serializer = CreateOCSSubscriberSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        ocs_instance_pk = serializer.validated_data['ocs_instance_pk']
        imsi = serializer.validated_data['imsi']
        phone_number = serializer.validated_data['phone_number']
        offering_id = serializer.validated_data['offering_id']
        initial_balance_bytes = serializer.validated_data.get('initial_balance_bytes', 1000000000)  # 1GB default

        try:
            # Get the OCS instance
            ocs_instance = OCSInstance.objects.get(pk=ocs_instance_pk)

            # Check if user already has a subscriber in this specific instance
            if OCSSubscriber.objects.filter(
                user=request.user,
                ocs_instance=ocs_instance
            ).exists():
                return Response(
                    {"error": "You already have a subscriber in this OCS instance."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Create subscriber via OCS API
            ocs_client = OCSAPIClient(ocs_instance)
            result = ocs_client.create_subscriber(
                imsi=imsi,
                phone_number=phone_number,
                offering_id=offering_id,
                initial_balance_bytes=initial_balance_bytes
            )

            if not result["success"]:
                return Response(
                    {"error": f"Failed to create subscriber in OCS: {result['error']}"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            # Create OCSSubscriber record
            ocs_subscriber = OCSSubscriber.objects.create(
                user=request.user,
                ocs_instance=ocs_instance,
                imsi=imsi,
                phone_number=phone_number,
                service_id=result["service_id"],
                product_id=result["product_id"]
            )

            # Update user's IMSI field
            request.user.imsi = imsi
            request.user.save()

            response_serializer = OCSSubscriberSerializer(ocs_subscriber)
            return Response(
                response_serializer.data,
                status=status.HTTP_201_CREATED
            )

        except OCSInstance.DoesNotExist:
            return Response(
                {"error": "OCS instance not found."},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Error creating OCS subscriber: {str(e)}")
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(detail=True, methods=['get'], url_path='get-balance')
    def get_balance(self, request, pk=None):
        """
        Get current balance for an OCS subscriber.
        """
        ocs_subscriber = self.get_object()

        try:
            ocs_client = OCSAPIClient(ocs_subscriber.ocs_instance)
            balance_result = ocs_client.get_subscriber_balance(ocs_subscriber.product_id)

            if not balance_result["success"]:
                return Response(
                    {"error": f"Failed to fetch balance: {balance_result['error']}"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            return Response(balance_result, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error getting subscriber balance: {str(e)}")
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(
        detail=True,
        methods=['post'],
        url_path='manual-topup',
        permission_classes=[IsSuperUserOrAPIKeyUserOrNetworkAdmin]
    )
    def manual_topup(self, request, pk=None):
        """
        Manually add balance to an OCS subscriber (admin only).
        """
        ocs_subscriber = self.get_object()
        serializer = TopUpBalanceSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        amount_bytes = serializer.validated_data['amount_bytes']
        description = serializer.validated_data.get('description', 'Manual balance top-up')

        try:
            ocs_client = OCSAPIClient(ocs_subscriber.ocs_instance)
            result = ocs_client.top_up_balance(
                product_id=ocs_subscriber.product_id,
                amount_bytes=amount_bytes,
                description=description
            )

            if not result["success"]:
                return Response(
                    {"error": f"Failed to top up balance: {result['error']}"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            return Response(
                {
                    "success": True,
                    "message": f"Successfully added {amount_bytes / (1024*1024*1024):.2f} GB to {ocs_subscriber.user.username}",
                    "new_balance": result["new_balance"]
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            logger.error(f"Error adding manual top-up: {str(e)}")
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(detail=False, methods=['get'], url_path='my-instances')
    def my_instances(self, request):
        """
        Get user's OCS registrations and available instances for registration.
        Users can register with multiple OCS instances.
        """
        # Get user's OCS registrations
        user_subscribers = OCSSubscriber.objects.filter(
            user=request.user
        ).select_related('ocs_instance')

        # Get all active instances
        all_instances = OCSInstance.objects.filter(is_active=True)
        all_instances_data = PublicOCSInstanceSerializer(all_instances, many=True).data

        # Get instances where user is already registered
        registered_instance_ids = user_subscribers.values_list('ocs_instance_id', flat=True)
        
        # Separate registered and available instances
        registered_instances = [
            instance for instance in all_instances_data 
            if instance['id'] in registered_instance_ids
        ]
        available_instances = [
            instance for instance in all_instances_data 
            if instance['id'] not in registered_instance_ids
        ]

        # Serialize user's registrations with more details
        registered_data = []
        for subscriber in user_subscribers:
            registered_data.append({
                'id': subscriber.id,
                'imsi': subscriber.imsi,
                'phone_number': subscriber.phone_number,
                'service_id': subscriber.service_id,
                'product_id': subscriber.product_id,
                'ocs_instance': {
                    'id': subscriber.ocs_instance.id,
                    'name': subscriber.ocs_instance.name,
                    'base_url': subscriber.ocs_instance.base_url,
                    'accepts_crypto': subscriber.ocs_instance.accepts_crypto
                }
            })

        return Response({
            'registered_instances': registered_data,
            'available_instances': available_instances,
            'total_registered': len(registered_data),
            'total_available': len(available_instances)
        }, status=status.HTTP_200_OK)

    @action(detail=False, methods=['get'], url_path='my-mappings')
    def my_mappings(self, request):
        """
        Get user's OCS mappings (simplified onboarding) and available instances for registration.
        Uses the OCSMapping model which links user + instance + imsi -> service_id + product_id.
        """
        # Get user's OCS mappings
        user_mappings = OCSMapping.objects.filter(
            user=request.user
        ).select_related('ocs_instance')

        # Get all active instances
        all_instances = OCSInstance.objects.filter(is_active=True)
        all_instances_data = PublicOCSInstanceSerializer(all_instances, many=True).data

        # Get instances where user is already registered (has mappings)
        registered_instance_ids = user_mappings.values_list('ocs_instance_id', flat=True).distinct()
        
        # Separate registered and available instances
        registered_instances = [
            instance for instance in all_instances_data 
            if instance['id'] in registered_instance_ids
        ]
        available_instances = [
            instance for instance in all_instances_data 
            if instance['id'] not in registered_instance_ids
        ]

        # Serialize user's mappings with more details
        registered_data = []
        for mapping in user_mappings:
            registered_data.append({
                'id': mapping.id,
                'imsi': mapping.imsi,
                'service_id': mapping.service_id,
                'product_id': mapping.product_id,
                'created_at': mapping.created_at.isoformat() if mapping.created_at else None,
                'updated_at': mapping.updated_at.isoformat() if mapping.updated_at else None,
                'ocs_instance': {
                    'id': mapping.ocs_instance.id,
                    'name': mapping.ocs_instance.name,
                    'base_url': mapping.ocs_instance.base_url,
                    'accepts_crypto': mapping.ocs_instance.accepts_crypto
                }
            })

        return Response({
            'registered_instances': registered_data,
            'available_instances': available_instances,
            'total_registered': len(registered_data),
            'total_available': len(available_instances)
        }, status=status.HTTP_200_OK)

    @action(detail=False, methods=['get'], url_path='mapping-bundles')
    def mapping_bundles(self, request):
        """
        Get available data bundles for a specific mapping (OCS instance).
        Requires mapping_id query parameter.
        """
        mapping_id = request.query_params.get('mapping_id')
        if not mapping_id:
            return Response(
                {"error": "mapping_id query parameter is required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            mapping = OCSMapping.objects.select_related('ocs_instance').get(
                id=mapping_id,
                user=request.user
            )
        except OCSMapping.DoesNotExist:
            return Response(
                {"error": "Mapping not found"},
                status=status.HTTP_404_NOT_FOUND
            )

        # Get active bundles for this instance
        bundles = DataBundle.objects.filter(
            ocs_instance=mapping.ocs_instance,
            is_active=True
        ).order_by('price')

        serializer = DataBundleSerializer(bundles, many=True)
        return Response({
            'mapping_id': mapping.id,
            'imsi': mapping.imsi,
            'ocs_instance': {
                'id': mapping.ocs_instance.id,
                'name': mapping.ocs_instance.name,
            },
            'bundles': serializer.data,
            'total_bundles': len(serializer.data)
        }, status=status.HTTP_200_OK)

    @action(detail=False, methods=['get'], url_path='mapping-history')
    def mapping_history(self, request):
        """
        Get top-up history for a specific mapping.
        Requires mapping_id query parameter.
        """
        mapping_id = request.query_params.get('mapping_id')
        if not mapping_id:
            return Response(
                {"error": "mapping_id query parameter is required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            mapping = OCSMapping.objects.select_related('ocs_instance').get(
                id=mapping_id,
                user=request.user
            )
        except OCSMapping.DoesNotExist:
            return Response(
                {"error": "Mapping not found"},
                status=status.HTTP_404_NOT_FOUND
            )

        # Get top-up history for this mapping
        history = TopUpHistory.objects.filter(
            mapping=mapping
        ).select_related('bundle').order_by('-created_at')

        serializer = TopUpHistorySerializer(history, many=True)
        return Response({
            'mapping_id': mapping.id,
            'imsi': mapping.imsi,
            'product_id': mapping.product_id,
            'ocs_instance': {
                'id': mapping.ocs_instance.id,
                'name': mapping.ocs_instance.name,
            },
            'history': serializer.data,
            'total_topups': len(serializer.data)
        }, status=status.HTTP_200_OK)

    @action(detail=False, methods=['get'], url_path='mapping-balance')
    def mapping_balance(self, request):
        """
        Get current balance for a specific mapping.
        Requires mapping_id query parameter.
        Returns sum total of all buckets for the mapping's product.
        """
        mapping_id = request.query_params.get('mapping_id')
        if not mapping_id:
            return Response(
                {"error": "mapping_id query parameter is required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            mapping = OCSMapping.objects.select_related('ocs_instance').get(
                id=mapping_id,
                user=request.user
            )
        except OCSMapping.DoesNotExist:
            return Response(
                {"error": "Mapping not found"},
                status=status.HTTP_404_NOT_FOUND
            )

        # Get balance from OCS
        try:
            client = OCSClientManager.get_client(mapping.ocs_instance)
            balance_mgmt = BalanceManagement(client)
            
            buckets = balance_mgmt.list_buckets(mapping.product_id)
            
            # Sum up all remainedAmount values
            total_bytes = 0
            bucket_details = []
            
            for bucket in buckets:
                remained_amount = bucket.get('remainedAmount', {})
                amount_str = remained_amount.get('amount', '0b')
                units = remained_amount.get('units', 'octets')
                
                # Parse amount string (e.g., "200000b" or "1048576000b")
                if amount_str.endswith('b'):
                    try:
                        bucket_bytes = int(amount_str[:-1])
                        total_bytes += bucket_bytes
                        bucket_details.append({
                            'bucket_id': bucket.get('id'),
                            'amount_bytes': bucket_bytes,
                            'amount_formatted': OCSSubscriberViewSet._format_bytes(bucket_bytes),
                            'units': units
                        })
                    except ValueError:
                        logger.warning(f"Could not parse bucket amount: {amount_str}")
                        continue
                else:
                    # Try parsing as integer without 'b' suffix
                    try:
                        bucket_bytes = int(amount_str)
                        total_bytes += bucket_bytes
                        bucket_details.append({
                            'bucket_id': bucket.get('id'),
                            'amount_bytes': bucket_bytes,
                            'amount_formatted': OCSSubscriberViewSet._format_bytes(bucket_bytes),
                            'units': units
                        })
                    except ValueError:
                        logger.warning(f"Could not parse bucket amount: {amount_str}")
                        continue
            
            return Response({
                'mapping_id': mapping.id,
                'imsi': mapping.imsi,
                'product_id': mapping.product_id,
                'ocs_instance': {
                    'id': mapping.ocs_instance.id,
                    'name': mapping.ocs_instance.name,
                },
                'balance': {
                    'total_bytes': total_bytes,
                    'total_mb': round(total_bytes / (1024 * 1024), 2),
                    'total_gb': round(total_bytes / (1024 ** 3), 2),
                    'total_formatted': OCSSubscriberViewSet._format_bytes(total_bytes),
                    'buckets_count': len(bucket_details),
                    'buckets': bucket_details
                }
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error getting balance for mapping {mapping_id}: {str(e)}")
            return Response(
                {"error": f"Failed to retrieve balance: {str(e)}"},
                status=status.HTTP_502_BAD_GATEWAY
            )
    
    @staticmethod
    def _format_bytes(bytes_value):
        """Format bytes to human-readable string."""
        if bytes_value == 0:
            return "0 B"
        
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} PB"


class DataBundleViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing Data Bundles.
    Regular users can list and retrieve bundles.
    Network admins and superusers can create, update, and delete bundles.
    """
    serializer_class = DataBundleSerializer
    authentication_classes = [KeycloakAuthentication]
    permission_classes = [IsAuthenticated]
    queryset = DataBundle.objects.all()

    def get_queryset(self):
        """
        Filter bundles by ocs_instance query parameter if provided.
        Only return active bundles for non-admin users.
        """
        queryset = DataBundle.objects.all()
        user = self.request.user

        # Filter by ocs_instance if provided
        ocs_instance_id = self.request.query_params.get('ocs_instance')
        if ocs_instance_id:
            queryset = queryset.filter(ocs_instance_id=ocs_instance_id)

        # Only show active bundles to regular users
        if not user.is_superuser and not user.has_perm('core.network_admin'):
            queryset = queryset.filter(is_active=True)

        return queryset.order_by('-created_at')

    def get_permissions(self):
        """
        Admin operations require superuser or network admin permissions.
        """
        if self.action in ['create', 'update', 'partial_update', 'destroy']:
            return [IsSuperUserOrAPIKeyUserOrNetworkAdmin()]
        return [IsAuthenticated()]

    @action(detail=False, methods=['get'], url_path='my-bundles')
    def my_bundles(self, request):
        """
        Get bundles for instances where the user has a subscriber.
        """
        # Get all OCSInstances where the user has a subscriber
        user_instances = OCSSubscriber.objects.filter(
            user=request.user
        ).values_list('ocs_instance', flat=True)

        if not user_instances:
            return Response(
                {"error": "You must register with an OCS instance first to view available bundles."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Get active bundles for those instances
        bundles = DataBundle.objects.filter(
            ocs_instance__in=user_instances,
            is_active=True
        ).order_by('ocs_instance', 'price')

        serializer = self.get_serializer(bundles, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)



class DataPurchaseViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ViewSet for viewing data purchase history.
    Users can only see their own purchases.
    Network admins can see purchases for their instances.
    """
    serializer_class = DataPurchaseSerializer
    authentication_classes = [KeycloakAuthentication]
    permission_classes = [IsAuthenticated]
    queryset = DataPurchase.objects.all()

    def get_queryset(self):
        """
        Filter purchases based on user permissions and query parameters.
        Supports filtering by ocs_instance.
        """
        user = self.request.user

        # Determine base queryset based on user permissions
        if user.is_superuser:
            queryset = DataPurchase.objects.all()
        # Network admins see purchases for their instances
        elif user.has_perm('core.network_admin'):
            admin_instances = OCSInstance.objects.filter(
                administrators=user
            )
            queryset = DataPurchase.objects.filter(
                bundle__ocs_instance__in=admin_instances
            )
        # Regular users see only their own purchases
        else:
            queryset = DataPurchase.objects.filter(user=user)

        # Apply ocs_instance filter if provided
        ocs_instance_id = self.request.query_params.get('ocs_instance')
        if ocs_instance_id:
            queryset = queryset.filter(
                bundle__ocs_instance_id=ocs_instance_id
            )

        return queryset.order_by('-purchase_date')

    @action(detail=False, methods=['get'], url_path='my-purchases')
    def my_purchases(self, request):
        """
        Get detailed purchase history for the authenticated user.
        """
        purchases = self.get_queryset()
        
        # Add pagination
        page = self.paginate_queryset(purchases)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        
        serializer = self.get_serializer(purchases, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


# New simplified endpoints

def _resolve_ocs_instance(provided_id: int | None):
    if not provided_id:
        return None
    try:
        return OCSInstance.objects.get(id=provided_id, is_active=True)
    except OCSInstance.DoesNotExist:
        return None


class OnboardView(APIView):
    authentication_classes = [KeycloakAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = OnboardRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        imsi = serializer.validated_data["imsi"]
        multi_session = serializer.validated_data.get("multiSession", False)
        ocs_instance_id = serializer.validated_data.get("ocs_instance_id")

        ocs_instance = _resolve_ocs_instance(ocs_instance_id)
        if not ocs_instance:
            return Response({"error": "OCS instance not found. Provide a valid ocs_instance_id."}, status=status.HTTP_400_BAD_REQUEST)

        client = OCSClientManager.get_client(ocs_instance)
        service_inventory = ServiceInventory(client)
        product_inventory = ProductInventory(client)

        # Hardcoded AKA values for testing
        service_aka_k = "8baf473f2f8fd09487cccbd7097c6862"
        service_aka_opc = "11111111111111111111111111111111"

        service_payload = {
            "serviceCharacteristic": [
                {"name": "serviceIdentity", "value": imsi},
                {"name": "serviceAkaK", "value": service_aka_k},
                {"name": "serviceAkaOPc", "value": service_aka_opc},
                {"name": "multiSession", "valueType": "boolean", "value": multi_session},
            ],
            "state": "active",
            "serviceSpecification": {"id": "1", "href": "/catalogManagement/v2/serviceSpecification/1"},
        }

        try:
            service_resp = service_inventory.create_service(service_payload)
        except Exception as e:
            logger.error(f"OCS service creation failed: {e}")
            return Response({"error": f"Failed to create service: {e}"}, status=status.HTTP_502_BAD_GATEWAY)

        service_id = service_resp.get("id")
        service_href = service_resp.get("href")
        if not (service_id and service_href):
            return Response({"error": "Service ID or href missing from OCS response"}, status=status.HTTP_502_BAD_GATEWAY)

        product_payload = {
            "productOffering": {
                "id": settings.OCS_DEFAULT_PRODUCT_OFFERING,
                "name": settings.OCS_DEFAULT_PRODUCT_OFFERING,
            },
            "realizingService": [{"id": service_id, "href": service_href}],
        }

        try:
            product_resp = product_inventory.create_product(product_payload)
        except Exception as e:
            logger.error(f"OCS product creation failed: {e}")
            return Response({"error": f"Failed to create product: {e}"}, status=status.HTTP_502_BAD_GATEWAY)

        # Persist slim mapping (user must be authenticated)
        try:
            OCSMapping.objects.update_or_create(
                user=request.user,
                ocs_instance=ocs_instance,
                imsi=imsi,
                defaults={
                    "service_id": service_id,
                    "product_id": product_resp.get("id", ""),
                },
            )
        except Exception as e:
            logger.warning(f"Failed to persist OCSMapping: {e}")

        return Response(
            {
                "service": service_resp,
                "product": product_resp,
                "productId": product_resp.get("id"),
            },
            status=status.HTTP_201_CREATED,
        )


class TopupView(APIView):
    authentication_classes = [KeycloakAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        logger.debug(f"TopupView request: {request.data}")
        serializer = TopupRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        bundle_id = serializer.validated_data["bundle_id"]
        imsi = serializer.validated_data.get("imsi")
        description = serializer.validated_data.get("description")

        # Load bundle and resolve OCS instance + amount
        try:
            bundle = DataBundle.objects.select_related("ocs_instance").get(id=bundle_id, is_active=True)
        except DataBundle.DoesNotExist:
            return Response({"error": "Bundle not found or inactive"}, status=status.HTTP_404_NOT_FOUND)

        ocs_instance = bundle.ocs_instance
        amount_bytes = int(bundle.data_mb) * 1024 * 1024

        # Resolve mapping for productId
        if imsi:
            mapping = OCSMapping.objects.filter(user=request.user, ocs_instance=ocs_instance, imsi=imsi).first()
            if not mapping:
                return Response({"error": "No mapping found for provided IMSI on this instance. Onboard first."}, status=status.HTTP_400_BAD_REQUEST)
        else:
            mappings = list(OCSMapping.objects.filter(user=request.user, ocs_instance=ocs_instance)[:2])
            if len(mappings) == 1:
                mapping = mappings[0]
            else:
                return Response({"error": "Multiple or no mappings found for this instance. Provide imsi to disambiguate."}, status=status.HTTP_400_BAD_REQUEST)

        product_id = mapping.product_id

        # Handle payment based on bundle payment method
        transaction = None
        payment_status = "pending"
        
        if bundle.payment_method == "crypto":
            # Crypto payment flow
            # Check that the instance accepts crypto payments
            if not ocs_instance.accepts_crypto:
                return Response(
                    {
                        "error": "This OCS instance does not accept cryptocurrency payments.",
                        "accepts_crypto": ocs_instance.accepts_crypto
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Get user's wallet
            wallet = Wallet.objects.filter(user=request.user).first()
            if not wallet:
                return Response(
                    {"error": "User wallet not found. Please create a wallet first."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Get network admin wallet address
            network_admin = ocs_instance.administrators.first()
            if not network_admin:
                return Response(
                    {"error": "No network admin found for this OCS instance."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            admin_wallet = Wallet.objects.filter(user=network_admin).first()
            if not admin_wallet:
                return Response(
                    {"error": "Network admin does not have a wallet."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Decrypt the user's private key
            try:
                decrypted_private_key = decrypt_private_key(wallet.private_key)
            except Exception as e:
                logger.error(f"Failed to decrypt wallet private key: {str(e)}")
                return Response(
                    {"error": "Failed to decrypt wallet private key."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            # Perform the crypto transaction
            try:
                crypto_utils = CryptoUtils(
                    contract_abi_path=settings.ABI_FILE_PATH,
                    contract_address=settings.CONTRACT_ADDRESS,
                    registry=settings.FAUCET_AND_INDEX_ENABLED,
                    faucet=settings.FAUCET_AND_INDEX_ENABLED,
                )

                tx_receipt = crypto_utils.send_to_wallet_address(
                    wallet.address,
                    decrypted_private_key,
                    admin_wallet.address,
                    float(bundle.price)
                )
                
                # Record the transaction
                transaction = Transaction.objects.create(
                    sender=request.user,
                    recipient_address=admin_wallet.address,
                    recipient=network_admin,
                    amount=float(bundle.price),
                    category="OCS_DATA_BUNDLE",
                    transaction_hash=tx_receipt.transactionHash.hex(),
                    block_number=tx_receipt.blockNumber,
                    block_hash=tx_receipt.blockHash.hex(),
                    gas_used=tx_receipt.gasUsed,
                    token="KRONE",
                )
                payment_status = "success"
                logger.debug(f"Crypto payment successful for bundle {bundle.id}: {tx_receipt.transactionHash.hex()}")
                
            except Exception as e:
                logger.error(f"Crypto transaction failed: {str(e)}")
                payment_status = "failed"
                return Response(
                    {"error": f"Cryptocurrency payment failed: {str(e)}"},
                    status=status.HTTP_400_BAD_REQUEST
                )
                
        elif bundle.payment_method == "1foryou":
            # 1FourYou payment flow
            oneforyou_pin_raw = serializer.validated_data.get('oneforyou_pin')
            phone_number = serializer.validated_data.get('phone_number')
            
            if not oneforyou_pin_raw or not phone_number:
                return Response(
                    {"error": "1FourYou PIN and phone number are required for 1foryou payment method."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Normalize PIN by removing spaces, hyphens, etc.
            oneforyou_pin = normalize_oneforyou_pin(oneforyou_pin_raw)
            logger.debug(f"Normalized 1FourYou PIN: '{oneforyou_pin_raw}' -> '{oneforyou_pin}'")
            
            # Convert bundle price to cents
            amount_cents = int(bundle.price * 100)
            
            try:
                # Redeem 1FourYou voucher using the shared client instance
                redemption_response = oneforyou_client.redeem_voucher(
                    voucher_pin=oneforyou_pin,
                    amount_cents=amount_cents,
                    phone_number=phone_number
                )
                
                logger.debug(f"1FourYou redemption successful for user {request.user.username}: {redemption_response}")
                
                # Extract reference and change voucher from response
                reference = redemption_response.get("reference", "")
                voucher_obj = redemption_response.get("voucher", {})
                
                # Extract change voucher details if present
                change_voucher_pin = None
                change_voucher_amount = None
                if voucher_obj:
                    change_voucher_pin = voucher_obj.get("pin")
                    change_voucher_amount_cents = voucher_obj.get("amount", 0)
                    # Convert cents to ZAR (divide by 100)
                    if change_voucher_amount_cents:
                        change_voucher_amount = Decimal(str(change_voucher_amount_cents)) / 100
                
                # Create transaction record for 1FourYou payment
                # Store the original (raw) PIN in sender_address for reference
                transaction = Transaction.objects.create(
                    sender=request.user,
                    recipient_address="1FourYou",
                    sender_address=oneforyou_pin_raw,  # Store original format for reference
                    amount=Decimal(str(bundle.price)),
                    category="OCS_DATA_BUNDLE",
                    token="ZAR",
                    oneforyou_reference=reference,
                    change_voucher_pin=change_voucher_pin,
                    change_voucher_amount=change_voucher_amount,
                )
                payment_status = "success"
                logger.debug(f"1FourYou payment successful for bundle {bundle.id}: {reference}")
                
            except Exception as e:
                logger.error(f"1FourYou redemption failed for user {request.user.username}: {str(e)}")
                payment_status = "failed"
                return Response(
                    {"error": f"1FourYou payment failed: {str(e)}"},
                    status=status.HTTP_400_BAD_REQUEST
                )
        else:
            # Other payment methods - log and proceed
            logger.debug(
                f"Payment method '{bundle.payment_method}' for bundle {bundle.id}. "
                f"Proceeding with top-up."
            )
            payment_status = "pending"

        # Perform OCS adjustment
        # Use BalanceManagement directly to allow custom units
        instance = ocs_instance

        client = OCSClientManager.get_client(instance)
        balance_mgmt = BalanceManagement(client)

        try:
            # Try with "octets" units first (OCS standard format)
            try:
                result = balance_mgmt.create_adjustment(
                    product_id=product_id,
                    amount=amount_bytes,
                    units="octets",  # OCS expects "octets" not "bytes"
                    description=description or f"Top-up via bundle {bundle.name} ({bundle.data_mb}MB)"
                )
            except Exception as e1:
                # If that fails, try constructing payload manually to match exact OCS format
                logger.warning(f"Standard adjustment failed: {e1}. Trying manual payload format...")
                
            # Record successful top-up
            topup_history = TopUpHistory.objects.create(
                mapping=mapping,
                bundle=bundle,
                amount_bytes=amount_bytes,
                adjustment_id=result.get("id", ""),
                status="success",
                description=description or f"Top-up via bundle {bundle.name} ({bundle.data_mb}MB)"
            )
            
            # Link transaction if payment was used
            if transaction:
                if transaction.transaction_hash:
                    # Crypto transaction
                    logger.debug(
                        f"Top-up {topup_history.id} completed with crypto transaction "
                        f"{transaction.transaction_hash}"
                    )
                elif transaction.oneforyou_reference:
                    # 1FourYou transaction
                    logger.debug(
                        f"Top-up {topup_history.id} completed with 1FourYou transaction "
                        f"{transaction.oneforyou_reference}"
                    )
        except Exception as e:
            logger.error(f"OCS top-up failed: {e}")
            # Record failed top-up
            try:
                TopUpHistory.objects.create(
                    mapping=mapping,
                    bundle=bundle,
                    amount_bytes=amount_bytes,
                    status="failed",
                    description=f"Failed: {str(e)}"
                )
            except Exception as history_error:
                logger.error(f"Failed to record top-up history: {history_error}")
            return Response({"error": f"Failed to top up: {e}"}, status=status.HTTP_502_BAD_GATEWAY)

        response_data = {
            "success": True,
            "adjustment": result,
            "productId": product_id,
            "amount_bytes": amount_bytes,
            "payment": {
                "method": bundle.payment_method,
                "status": payment_status,
                "amount": float(bundle.price)
            }
        }
        
        # Include transaction details if payment was used
        if transaction:
            if transaction.transaction_hash:
                # Crypto transaction
                response_data["payment"]["transaction_hash"] = transaction.transaction_hash
                response_data["payment"]["block_number"] = transaction.block_number
            elif transaction.oneforyou_reference:
                # 1FourYou transaction
                response_data["payment"]["transaction_reference"] = transaction.oneforyou_reference
                
                # Include change voucher if present
                if transaction.change_voucher_pin:
                    response_data["change_voucher"] = {
                        "pin": transaction.change_voucher_pin,
                        "amount": float(transaction.change_voucher_amount) if transaction.change_voucher_amount else None,
                        "message": "Please save this voucher PIN for future use"
                    }
        
        return Response(response_data, status=status.HTTP_200_OK)
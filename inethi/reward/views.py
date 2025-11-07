from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.decorators import action
from django_celery_beat.models import PeriodicTask, IntervalSchedule
import json
from utils.keycloak import KeycloakAuthentication
from .models import Reward, UptimeRewardTransaction
from .serializers import RewardSerializer, UptimeRewardTransactionSerializer
from .tasks import process_reward
from django.utils.timezone import now, timedelta
from utils.super_user_or_api_key_or_network_admin import (
    IsSuperUserOrAPIKeyUserOrNetworkAdmin
)
import logging

logger = logging.getLogger('reward')


def schedule_recurring_reward(reward_id, interval_minutes):
    """
    Schedules a recurring Celery Beat task with the provided interval.
    """
    schedule, created = IntervalSchedule.objects.get_or_create(
        every=interval_minutes,
        period=IntervalSchedule.MINUTES
    )

    task = PeriodicTask.objects.create(
        interval=schedule,
        name=f"reward_task_{reward_id}",
        task="reward.tasks.process_reward",
        args=json.dumps([reward_id]),
        start_time=now() + timedelta(seconds=10)
    )

    return task.id


class RewardViewSet(viewsets.ModelViewSet):
    """API for managing rewards"""

    queryset = Reward.objects.all()
    serializer_class = RewardSerializer
    authentication_classes = [KeycloakAuthentication]
    permission_classes = [IsSuperUserOrAPIKeyUserOrNetworkAdmin]

    def get_queryset(self):
        user = self.request.user
        logger.debug(f"Fetching rewards for user {user}")
        if user.is_superuser or not user.has_perm('core.network_admin'):
            return Reward.objects.all()
        logger.debug(
            f"User {user} is network admin, filtering rewards by their networks"
        )
        return Reward.objects.filter(network__admin=user)

    @action(detail=False, methods=['post'])
    def setup(self, request):
        logger.debug(f"Reward setup requested by user {request.user}")
        if (request.user.has_perm('core.network_admin') and
                not request.user.is_superuser):
            network_id = request.data.get('network')
            if not network_id:
                # Try to infer network from device
                device_id = request.data.get('device')
                if device_id:
                    from network.models import Host
                    try:
                        device = Host.objects.get(id=device_id)
                        if device.network:
                            network_id = device.network.id
                            logger.debug(
                                f"Inferred network {network_id} from device {device_id}"
                            )
                            request.data['network'] = network_id
                        else:
                            logger.error(f"Device {device_id} has no associated network.")
                            return Response(
                                {"error": "Device has no associated network."},
                                status=status.HTTP_400_BAD_REQUEST
                            )
                    except Host.DoesNotExist:
                        logger.error(f"Device {device_id} not found.")
                        return Response(
                            {"error": "Device not found."},
                            status=status.HTTP_400_BAD_REQUEST
                        )
                else:
                    logger.error(
                        "Network field required, could not infer from device."
                    )
                    return Response(
                        {"error": "Network field is required for network admins."},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            try:
                from network.models import Network
                network = Network.objects.get(id=network_id)
            except Exception as e:
                logger.error(f"Network {network_id} not found: {e}")
                return Response(
                    {"error": "Network not found."},
                    status=status.HTTP_404_NOT_FOUND
                )
            if network.admin != request.user:
                logger.error(
                    f"User {request.user} not authorized for network {network_id}"
                )
                return Response(
                    {"error": "Unauthorized to create rewards for this network."},
                    status=status.HTTP_403_FORBIDDEN
                )
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            reward = serializer.save()
            logger.debug(f"Reward {reward.id} created by user {request.user}")
            if reward.once_off:
                task = process_reward.delay(reward.id)
                reward.celery_task_id = task.id
            else:
                interval_minutes = request.data.get('interval_minutes', 60)
                reward.interval_minutes = interval_minutes
                task_id = schedule_recurring_reward(reward.id, interval_minutes)
                reward.celery_task_id = task_id
            reward.save()
            return Response({
                'message': 'Reward setup successfully.',
                'reward_id': reward.id
            }, status=status.HTTP_201_CREATED)
        logger.error(f"Reward creation failed: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None):
        logger.debug(f"Reward update requested for id {pk} by user {request.user}")
        reward = self.get_object()
        old_task_id = reward.celery_task_id
        serializer = self.get_serializer(
            reward,
            data=request.data,
            partial=True
        )
        if serializer.is_valid():
            updated_reward = serializer.save()
            if not updated_reward.once_off:
                if old_task_id:
                    try:
                        from django_celery_beat.models import PeriodicTask
                        task = PeriodicTask.objects.get(
                            name=f"reward_task_{reward.id}"
                        )
                        task.delete()
                    except Exception as e:
                        logger.warning(f"Could not delete old periodic task: {e}")
                interval_minutes = updated_reward.interval_minutes or 60
                task_id = schedule_recurring_reward(
                    updated_reward.id,
                    interval_minutes
                )
                updated_reward.celery_task_id = task_id
                updated_reward.is_canceled = False
                updated_reward.save()
            logger.debug(f"Reward {pk} updated by user {request.user}")
            return Response(serializer.data, status=status.HTTP_200_OK)
        logger.error(f"Reward update failed for id {pk}: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        logger.debug(f"Reward destroy requested for id {pk} by user {request.user}")
        try:
            reward = self.get_object()
            if reward.once_off and reward.celery_task_id:
                from celery import current_app
                current_app.control.revoke(
                    reward.celery_task_id,
                    terminate=True
                )
            else:
                try:
                    from django_celery_beat.models import PeriodicTask
                    task = PeriodicTask.objects.get(
                        name=f"reward_task_{reward.id}"
                    )
                    task.delete()
                except Exception as e:
                    logger.warning(f"Could not delete periodic task: {e}")
            reward.delete()
            logger.debug(f"Reward {pk} deleted by user {request.user}")
            return Response(
                {'message': 'Reward canceled and deleted successfully.'},
                status=status.HTTP_204_NO_CONTENT
            )
        except Reward.DoesNotExist:
            logger.error(f"Reward {pk} not found for deletion.")
            return Response(
                {'error': 'Reward not found.'},
                status=status.HTTP_404_NOT_FOUND
            )

    @action(detail=True, methods=['post'])
    def activate(self, request, pk=None):
        logger.debug(f"Reward activate requested for id {pk} by user {request.user}")
        try:
            reward = self.get_object()
            if not reward.is_cancelled:
                logger.debug(f"Reward {pk} is already active.")
                return Response(
                    {'message': 'Reward is already active.'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            reward.is_cancelled = False
            reward.save()
            if reward.once_off:
                task = process_reward.delay(reward.id)
                reward.celery_task_id = task.id
            else:
                interval_minutes = reward.interval_minutes or 60
                task_id = schedule_recurring_reward(
                    reward.id, interval_minutes
                )
                reward.celery_task_id = task_id
            reward.save()
            logger.debug(f"Reward {pk} activated by user {request.user}")
            return Response({
                'message': 'Reward activated successfully.'},
                status=status.HTTP_200_OK
            )
        except Reward.DoesNotExist:
            logger.error(f"Reward {pk} not found for activation.")
            return Response(
                {'error': 'Reward not found.'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Failed to activate reward {pk}: {e}")
            return Response(
                {'error': 'Failed to activate reward.'},
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        logger.debug(f"Reward cancel requested for id {pk} by user {request.user}")
        try:
            reward = self.get_object()
            if reward.once_off and reward.celery_task_id:
                from celery import current_app
                current_app.control.revoke(
                    reward.celery_task_id,
                    terminate=True
                )
                reward.celery_task_id = None
            else:
                try:
                    from django_celery_beat.models import PeriodicTask
                    task = PeriodicTask.objects.get(
                        name=f"reward_task_{reward.id}"
                    )
                    task.delete()
                    reward.celery_task_id = None
                except Exception as e:
                    logger.warning(f"No scheduled task found for reward {pk}: {e}")
                    return Response(
                        {'message': 'No scheduled task found.'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            reward.cancel()
            logger.debug(f"Reward {pk} cancelled by user {request.user}")
            return Response(
                {'message': 'Reward cancelled successfully.'},
                status=status.HTTP_200_OK
            )
        except Exception as e:
            logger.error(f"Failed to cancel reward {pk}: {e}")
            return Response(
                {'message': 'Failed to cancel reward.'},
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(detail=False, methods=['get'])
    def all(self, request):
        """
        Retrieve all rewards.
        """
        rewards = Reward.objects.all()
        serializer = self.get_serializer(rewards, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=False, methods=['get'], url_path='by-user')
    def rewards_by_user(self, request):
        """
        Retrieve rewards for the authenticated user.
        """
        rewards = Reward.objects.filter(user=request.user)
        serializer = self.get_serializer(rewards, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=False, methods=['get'], url_path='by-type')
    def rewards_by_type(self, request):
        """
        Retrieve rewards filtered by reward type.
        """
        reward_type = request.query_params.get('reward_type', None)
        if not reward_type:
            return Response(
                {"error": "Please provide a reward_type parameter."},
                status=status.HTTP_400_BAD_REQUEST
            )

        rewards = Reward.objects.filter(reward_type=reward_type)
        serializer = self.get_serializer(rewards, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class UptimeRewardTransactionViewSet(viewsets.ReadOnlyModelViewSet):
    """API for viewing uptime reward transactions"""

    queryset = UptimeRewardTransaction.objects.all()
    serializer_class = UptimeRewardTransactionSerializer

    @action(detail=False, methods=['get'], url_path='by-user')
    def transactions_by_user(self, request):
        """
        Retrieve reward transactions for the authenticated user.
        """
        transactions = UptimeRewardTransaction.objects.filter(
            reward__user=request.user
        )
        serializer = self.get_serializer(transactions, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

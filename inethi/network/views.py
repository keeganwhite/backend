from rest_framework import viewsets
from .models import Host, Ping, Network
from .serializers import HostSerializer, PingSerializer, NetworkSerializer
from django.db import connection
from rest_framework.decorators import (
    api_view,
    authentication_classes,
    permission_classes, action
)
from rest_framework.response import Response
from rest_framework import status
from utils.keycloak import KeycloakAuthentication
from utils.super_user_or_api_key import IsSuperUserOrAPIKeyUser
from utils.super_user_or_api_key_or_network_admin import (
    IsSuperUserOrAPIKeyUserOrNetworkAdmin
)
import re
from rest_framework.exceptions import PermissionDenied
from datetime import datetime, timedelta
import pytz


@api_view(['PUT'])
@authentication_classes([KeycloakAuthentication])
@permission_classes([IsSuperUserOrAPIKeyUserOrNetworkAdmin])
def update_host_by_identifier(request):
    """
    Updates a Host based on identifying fields in the payload.

    Expected payload:
    {
      "mac_address": "<mac address>" (optional),
      "ip_address": "<ip address>" (required if mac_address not provided),
      "network": "<network name>",  // required, searched by name for the current user
      ... other fields to update ...
    }

    The view searches for a host using:
      - If a mac_address is provided: host with that mac address (case-insensitive)
        within the network.
      - Otherwise, it uses ip_address and network.
    """
    payload = request.data
    network_name = payload.get("network")
    if not network_name:
        return Response(
            {"error": "Network name is required."},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Look up the network by name and ensure the requesting user is its admin.
    try:
        network = Network.objects.get(name=network_name, admins=request.user)
        print(network.id)
    except Network.DoesNotExist:
        return Response(
            {"error": "Network not found or not authorized."},
            status=status.HTTP_404_NOT_FOUND
        )

    mac_address = payload.get("mac_address")
    ip_address = payload.get("ip_address")

    # Filter hosts by the found network.
    hosts = Host.objects.filter(network=network)

    if mac_address:
        host = hosts.filter(mac_address__iexact=mac_address).first()
    else:
        if not ip_address:
            return Response(
                {"error": "Either mac_address or ip_address must be provided."},
                status=status.HTTP_400_BAD_REQUEST
            )
        host = hosts.filter(ip_address=ip_address).first()
        print(host)

    if not host:
        return Response(
            {"error": "Host not found."},
            status=status.HTTP_404_NOT_FOUND
        )

    # network admin (and not a superuser), then host belongs to network they manage.
    payload["network"] = network.id
    print(payload)
    serializer = HostSerializer(host, data=payload, partial=True)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['DELETE'])
@authentication_classes([KeycloakAuthentication])
@permission_classes([IsSuperUserOrAPIKeyUserOrNetworkAdmin])
def delete_host_by_identifier(request):
    """
    Deletes a Host based on identifying fields in the payload.

    Expected payload:
    {
      "mac_address": "<mac address>" (optional),
      "ip_address": "<ip address>" (required if mac_address not provided),
      "network": "<network name>"  // required, searched by name for the current user
    }

    The view searches for a host using:
      - If a mac_address is provided: host with that mac address (case-insensitive).
      - Otherwise, it uses ip_address and network.
    """
    payload = request.data
    network_name = payload.get("network")
    if not network_name:
        return Response(
            {"error": "Network name is required."},
            status=status.HTTP_400_BAD_REQUEST
        )

    # Look up the network by name for the current user.
    try:
        network = Network.objects.get(name=network_name, admins=request.user)
    except Network.DoesNotExist:
        return Response(
            {"error": "Network not found or not authorized."},
            status=status.HTTP_404_NOT_FOUND
        )

    mac_address = payload.get("mac_address")
    ip_address = payload.get("ip_address")

    # Filter hosts by this network.
    hosts = Host.objects.filter(network=network)
    if mac_address:
        host = hosts.filter(mac_address__iexact=mac_address).first()
    else:
        if not ip_address:
            return Response(
                {"error": "Either mac_address or ip_address must be provided."},
                status=status.HTTP_400_BAD_REQUEST
            )
        host = hosts.filter(ip_address=ip_address).first()

    if not host:
        return Response(
            {"error": "Host not found."},
            status=status.HTTP_404_NOT_FOUND
        )

    host.delete()
    return Response(
        {"message": "Host deleted successfully."},
        status=status.HTTP_200_OK
    )


@api_view(['GET'])
@authentication_classes([KeycloakAuthentication])
@permission_classes([IsSuperUserOrAPIKeyUserOrNetworkAdmin])
def aggregate_ping_view(request):
    """
    Returns aggregated ping data from one of the materialized views.

    Query Parameters:
      - host_ids (optional): Comma-separated list of host IDs (integers).
      - aggregation (optional): One of "15m", "60m", "6h", "12h", "24h",
          "7d", "30d", "90d", "365d". Defaults to "15m".
      - time_range (optional): Time range filter (e.g., "24 hours", "7 days").
          Defaults to "24 hours".

    Example URLs:
      /api/ping-aggregates/?aggregation=15m
      /api/ping-aggregates/?host_ids=1,2,3&aggregation=60m&time_range=7 days
    """
    # Get query parameters from DRF's request.query_params.
    host_ids_param = request.query_params.get('host_ids')
    aggregation_param = request.query_params.get('aggregation', '15m')
    network_id = request.query_params.get('network_id')
    time_range = request.query_params.get('time_range', '24 hours')

    # Map allowed aggregation values to your materialized view names.
    valid_aggregations = {
        '15m': 'network_ping_aggregate_15m',
        '60m': 'network_ping_aggregate_60m',
        '6h': 'network_ping_aggregate_6h',
        '12h': 'network_ping_aggregate_12h',
        '24h': 'network_ping_aggregate_24h',
        '7d': 'network_ping_aggregate_7d',
        '30d': 'network_ping_aggregate_30d',
        '90d': 'network_ping_aggregate_90d',
        '365d': 'network_ping_aggregate_365d',
    }
    if aggregation_param not in valid_aggregations:
        return Response(
            {"error": "Invalid aggregation value. Allowed values are: " +
                      ", ".join(valid_aggregations.keys())},
            status=status.HTTP_400_BAD_REQUEST
        )
    table_name = valid_aggregations[aggregation_param]

    # Validate and parse host_ids, if provided.
    # If network_id is provided, override host_ids.
    if network_id:
        try:
            network = Network.objects.get(id=network_id, admins=request.user)
        except Network.DoesNotExist:
            return Response(
                {"error": "Network not found or not authorized."},
                status=status.HTTP_404_NOT_FOUND
            )
        host_ids = list(network.hosts.values_list("id", flat=True))
    else:
        host_ids = []
        if host_ids_param:
            try:
                host_ids = [
                    int(x.strip()) for x in host_ids_param.split(',') if x.strip()
                ]
            except ValueError:
                return Response(
                    {"error": "host_ids must be a comma-separated list of integers."},
                    status=status.HTTP_400_BAD_REQUEST
                )

    # Build the optimized SQL query with time range filtering
    base_query = f"""
        SELECT bucket, host_id, uptime_percentage, total_pings
        FROM {table_name}
        WHERE bucket >= now() - interval %s
    """
    params = [time_range]

    if host_ids:
        # Create a list of placeholders for each host id.
        placeholders = ','.join(['%s'] * len(host_ids))
        base_query += f" AND host_id IN ({placeholders})"
        params.extend(host_ids)

    base_query += " ORDER BY bucket DESC, host_id;"

    # Execute the query using Django's database connection.
    try:
        with connection.cursor() as cursor:
            cursor.execute(base_query, params)
            columns = [col[0] for col in cursor.description]
            results = [dict(zip(columns, row)) for row in cursor.fetchall()]
    except Exception as e:
        return Response(
            {
                "error":
                    f"An error occurred while executing the query: {str(e)}"
            },
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

    return Response(results, status=status.HTTP_200_OK)


@api_view(['GET'])
@authentication_classes([KeycloakAuthentication])
@permission_classes([IsSuperUserOrAPIKeyUserOrNetworkAdmin])
def aggregate_uptime_view(request):
    """
    Returns aggregated uptime data for each host over a specified time period.
    Query Parameters:
      - period (optional): Look-back period (e.g., '15 minutes', '24 hours').
      - min_pings (optional): Minimum number of pings required to include a
      host.
      - host_ids (optional): Comma-separated list of host IDs to filter on.
    """
    # Default values
    period = request.query_params.get('period', '15 minutes')
    min_pings = int(request.query_params.get('min_pings', 1))
    host_ids_param = request.query_params.get('host_ids')
    network_id = request.query_params.get('network_id')

    # Validate host_ids if provided.
    host_ids = []
    if network_id:
        try:
            network = Network.objects.get(id=network_id, admins=request.user)
        except Network.DoesNotExist:
            return Response(
                {"error": "Network not found or not authorized."},
                status=status.HTTP_404_NOT_FOUND
            )
        host_ids = list(network.hosts.values_list("id", flat=True))
    elif host_ids_param:
        try:
            host_ids = [int(x.strip()) for x in host_ids_param.split(',') if x.strip()]
        except ValueError:
            return Response(
                {"error": "host_ids must be a comma-separated list of integers."},
                status=status.HTTP_400_BAD_REQUEST
            )

    # Build the optimized SQL query using TimescaleDB time_bucket for better performance
    sql = """
        SELECT
          host_id,
          AVG(CASE WHEN is_alive THEN 1.0 ELSE 0 END) * 100
          AS uptime_percentage,
          COUNT(*) AS total_pings
        FROM network_ping
        WHERE timestamp >= now() - interval %s
    """
    params = [period]

    # Optionally filter by host_ids if provided.
    if host_ids:
        placeholders = ','.join(['%s'] * len(host_ids))
        sql += f" AND host_id IN ({placeholders})"
        params.extend(host_ids)

    sql += """
        GROUP BY host_id
        HAVING COUNT(*) >= %s
        ORDER BY host_id;
    """
    params.append(min_pings)

    try:
        with connection.cursor() as cursor:
            cursor.execute(sql, params)
            columns = [col[0] for col in cursor.description]
            results = [dict(zip(columns, row)) for row in cursor.fetchall()]
    except Exception as e:
        return Response(
            {"error": f"Error executing query: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

    # --- Add missing hosts as offline (uptime 0%) ---
    # Build set of all expected host_ids
    if network_id:
        all_host_ids = set(
            Host.objects.filter(network=network).values_list('id', flat=True)
        )
    elif host_ids:
        all_host_ids = set(host_ids)
    else:
        all_host_ids = set(Host.objects.all().values_list('id', flat=True))

    # Find which hosts are missing from results
    result_host_ids = set(r['host_id'] for r in results)
    missing_host_ids = all_host_ids - result_host_ids
    for hid in missing_host_ids:
        results.append({
            'host_id': hid,
            'uptime_percentage': 0.0,
            'total_pings': 0
        })

    # --- Recalculate uptime for incomplete data ---
    # Parse period to get expected number of minutes
    period_minutes = 0
    period = period.strip().lower()
    # Support 'X minutes', 'X hours', 'X days', 'X weeks'
    match = re.match(r"(\d+)\s*minutes?", period)
    if match:
        period_minutes = int(match.group(1))
    else:
        match = re.match(r"(\d+)\s*hours?", period)
        if match:
            period_minutes = int(match.group(1)) * 60
        else:
            match = re.match(r"(\d+)\s*days?", period)
            if match:
                period_minutes = int(match.group(1)) * 60 * 24
            else:
                match = re.match(r"(\d+)\s*weeks?", period)
                if match:
                    period_minutes = int(match.group(1)) * 60 * 24 * 7
    expected_pings = period_minutes

    # For each result, if total_pings < expected_pings, treat missing as offline
    for r in results:
        if r['total_pings'] < expected_pings:
            alive_pings = float(r['uptime_percentage']) * float(r['total_pings']) / 100.0
            r['uptime_percentage'] = (
                (alive_pings / expected_pings) * 100 if expected_pings > 0 else 0.0
            )
            r['total_pings'] = expected_pings

    # Sort by host_id for consistency
    results.sort(key=lambda r: r['host_id'])

    return Response(results, status=status.HTTP_200_OK)


@api_view(['GET'])
@authentication_classes([KeycloakAuthentication])
@permission_classes([IsSuperUserOrAPIKeyUserOrNetworkAdmin])
def device_uptime_line_view(request):
    """
    Returns uptime data for a specific device over a selected period,
    aggregated on 5-minute intervals.

    Query Parameters:
      - host_id (required): The device ID.
      - period (optional): The look-back period
      (e.g., "30 minutes", "1 hour", etc.).
          Minimum allowed is 30 minutes. Defaults to "30 minutes".
    """
    host_id = request.query_params.get('host_id')
    period = request.query_params.get('period', '30 minutes')
    network_id = request.query_params.get('network_id')

    if not host_id:
        return Response(
            {"error": "host_id is required"},
            status=status.HTTP_400_BAD_REQUEST
        )
    try:
        host_id = int(host_id)
    except ValueError:
        return Response(
            {"error": "host_id must be an integer"},
            status=status.HTTP_400_BAD_REQUEST
        )

    if network_id:
        try:
            network = Network.objects.get(id=network_id, admins=request.user)
        except Network.DoesNotExist:
            return Response(
                {"error": "Network not found or not authorized."},
                status=status.HTTP_404_NOT_FOUND
            )
        try:
            host = Host.objects.get(id=host_id)
        except Host.DoesNotExist:
            return Response(
                {"error": "Host not found."},
                status=status.HTTP_404_NOT_FOUND
            )
        if not host.network or host.network.id != network.id:
            return Response(
                {"error": "Host does not belong to the selected network."},
                status=status.HTTP_403_FORBIDDEN
            )

    # If period is provided in minutes, enforce a minimum of 30 minutes.
    match = re.match(r"(\d+)\s*minutes", period)
    if match:
        minutes_val = int(match.group(1))
        if minutes_val < 30:
            return Response(
                {"error": "Minimum period is 30 minutes"},
                status=status.HTTP_400_BAD_REQUEST
            )
    bucket_param = '5 minutes'
    sql = f"""
        SELECT
            time_bucket('{bucket_param}', timestamp) AS bucket,
            AVG(CASE WHEN is_alive THEN 1.0 ELSE 0 END) * 100
            AS uptime_percentage,
            COUNT(*) AS total_pings
        FROM network_ping
        WHERE host_id = %s
          AND timestamp >= now() - interval %s
        GROUP BY bucket
        ORDER BY bucket;
    """
    params = [host_id, period]

    try:
        with connection.cursor() as cursor:
            cursor.execute(sql, params)
            columns = [col[0] for col in cursor.description]
            results = [dict(zip(columns, row)) for row in cursor.fetchall()]
    except Exception as e:
        return Response({"error": f"Error executing query: {str(e)}"},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # --- Fill in missing buckets as offline ---
    # Determine the time range
    now = datetime.utcnow().replace(second=0, microsecond=0, tzinfo=pytz.UTC)
    # Parse period to minutes
    period_minutes = 0
    period_str = period.strip().lower()
    match = re.match(r"(\d+)\s*minutes?", period_str)
    if match:
        period_minutes = int(match.group(1))
    else:
        match = re.match(r"(\d+)\s*hours?", period_str)
        if match:
            period_minutes = int(match.group(1)) * 60
        else:
            match = re.match(r"(\d+)\s*days?", period_str)
            if match:
                period_minutes = int(match.group(1)) * 60 * 24
            else:
                match = re.match(r"(\d+)\s*weeks?", period_str)
                if match:
                    period_minutes = int(match.group(1)) * 60 * 24 * 7
    start_time = now - timedelta(minutes=period_minutes)

    # Generate all expected 5-minute buckets
    bucket_interval = timedelta(minutes=5)
    expected_buckets = []
    t = start_time.replace(second=0, microsecond=0)
    # Align t to the next 5-minute mark
    t = t + timedelta(minutes=(5 - t.minute % 5) if t.minute % 5 != 0 else 0)
    while t <= now:
        expected_buckets.append(t)
        t += bucket_interval

    # Build a dict of results by bucket (as datetime)
    result_by_bucket = {}
    for r in results:
        # Parse bucket as datetime
        bucket_dt = r['bucket']
        if isinstance(bucket_dt, str):
            bucket_dt = datetime.fromisoformat(bucket_dt.replace('Z', '+00:00'))
        result_by_bucket[bucket_dt] = r

    # Fill in missing buckets
    filled_results = []
    for b in expected_buckets:
        r = result_by_bucket.get(b)
        if r:
            # Ensure bucket is a string
            bucket_val = r['bucket']
            if isinstance(bucket_val, datetime):
                bucket_val = bucket_val.isoformat().replace('+00:00', 'Z')
            elif isinstance(bucket_val, str) and bucket_val.endswith('+00:00'):
                bucket_val = bucket_val.replace('+00:00', 'Z')
            r = dict(r)  # copy to avoid mutating original
            r['bucket'] = bucket_val
            filled_results.append(r)
        else:
            filled_results.append({
                'bucket': b.isoformat().replace('+00:00', 'Z'),
                'uptime_percentage': 0.0,
                'total_pings': 0
            })

    # Sort by bucket just in case
    filled_results.sort(key=lambda r: r['bucket'])

    return Response(filled_results, status=status.HTTP_200_OK)


class HostViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows Hosts to be viewed or edited.
    Network admins can only manage hosts in networks they administer.
    """
    authentication_classes = [KeycloakAuthentication]
    permission_classes = [IsSuperUserOrAPIKeyUserOrNetworkAdmin]
    queryset = Host.objects.all()
    serializer_class = HostSerializer

    def get_queryset(self):
        user = self.request.user
        # For non-network admin users (or superusers), allow all hosts.
        if user.is_superuser or not user.has_perm('core.network_admin'):
            qs = Host.objects.all()
        else:
            # For network admins, only show hosts in networks they manage.
            qs = Host.objects.filter(network__admins=user)
        # Optionally filter by a network id passed as query parameter.
        network_id = self.request.query_params.get("network_id")
        if network_id:
            qs = qs.filter(network__id=network_id)
        return qs

    def perform_create(self, serializer):
        user = self.request.user
        # If a network admin is creating a host, ensure network is one they manage.
        if user.has_perm('core.network_admin') and not user.is_superuser:
            network = serializer.validated_data.get('network')
            if not network or user not in network.admins.all():
                raise PermissionDenied("Unauthorized to add hosts to this network.")
        serializer.save()


class PingViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows Ping results to be viewed or edited.
    """
    authentication_classes = [KeycloakAuthentication]
    permission_classes = [IsSuperUserOrAPIKeyUser]
    queryset = Ping.objects.all()
    serializer_class = PingSerializer


class NetworkViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows Networks to be viewed or edited.
    Superusers and API key users can view/edit all networks.
    Network admins can only view/edit networks they manage.
    """
    queryset = Network.objects.all()
    serializer_class = NetworkSerializer
    authentication_classes = [KeycloakAuthentication]
    permission_classes = [IsSuperUserOrAPIKeyUserOrNetworkAdmin]

    def get_queryset(self):
        user = self.request.user
        if user.is_superuser or not user.has_perm('core.network_admin'):
            return Network.objects.all()
        return Network.objects.filter(admins=user)

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)
        # Add the creator as the first admin
        network = serializer.instance
        network.admins.add(self.request.user)

    @action(detail=True, methods=["get"])
    def hosts(self, request, pk=None):
        """
        Returns all devices (hosts) for this network.
        """
        network = self.get_object()
        hosts = network.hosts.all()
        serializer = HostSerializer(hosts, many=True)
        return Response(serializer.data)


@api_view(['POST'])
@authentication_classes([KeycloakAuthentication])
@permission_classes([IsSuperUserOrAPIKeyUserOrNetworkAdmin])
def ingest_uptime_data(request):
    """
    Ingest uptime (ping) data from an external source.

    Expected payload:
    {
      "network": <network_id>,
      "network_admin": <network_admin_identifier>,
      # informational; actual authorization check is on current user
      "data": [
         { "host": <host_id>, "is_alive": <bool>, "timestamp": <ISO8601 timestamp> },
         ...
      ]
    }

    If the requesting user is a network admin (and not a superuser),
    they can only ingest data
    for networks they manage.
    """
    payload = request.data
    network_id = payload.get('network')
    data = payload.get('data')

    if not network_id or not data:
        return Response(
            {"error": "Missing required fields: network and data"},
            status=status.HTTP_400_BAD_REQUEST
        )

    try:
        network = Network.objects.get(id=network_id)
    except Network.DoesNotExist:
        return Response(
            {"error": "Network not found"},
            status=status.HTTP_404_NOT_FOUND
        )

    # network admin (and not a superuser), ensure they manage this network.
    if request.user.has_perm('core.network_admin') and not request.user.is_superuser:
        if request.user not in network.admins.all():
            return Response(
                {"error": "You are not authorized to ingest data for this network."},
                status=status.HTTP_403_FORBIDDEN
            )

    created = []
    errors = []
    for record in data:

        host_id = record.get('host')
        is_alive = record.get('is_alive')
        timestamp = record.get('timestamp')
        if host_id is None or is_alive is None:
            errors.append(f"Missing host or is_alive in record: {record}")
            print(f"Missing host or is_alive in record: {record}")
            continue

        try:
            host = Host.objects.get(id=host_id)
        except Host.DoesNotExist:
            errors.append(f"Host with id {host_id} not found")
            print(f"Host with id {host_id} not found")
            continue

        # Optionally, if the Host is already assigned to a network, verify it matches.
        if host.network and host.network != network:
            errors.append(
                f"Host {host_id} not associated with network {network_id}"
            )
            print(f"Host with id {host_id} is not associated with network {network_id}")
            continue

        # Create the Ping record associated with the given network.
        ping = Ping.objects.create(
            host=host,
            is_alive=is_alive,
            network=network,
            timestamp=timestamp if timestamp else None
        )
        created.append(ping.id)

    return Response(
        {"created": created, "errors": errors},
        status=status.HTTP_201_CREATED
    )

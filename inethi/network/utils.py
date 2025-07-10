import re
from django.db import connection


def calculate_uptime_percentage(host_id, period='15 minutes', min_pings=1):
    """
    Calculate uptime percentage for a host over a period,
    treating missing pings as offline.
    Returns (uptime_percentage, total_pings, expected_pings)
    """
    # Build the SQL query to aggregate data per host over the entire period.
    sql = (
        """
        SELECT
          AVG(CASE WHEN is_alive THEN 1.0 ELSE 0 END) * 100 AS uptime_percentage,
          COUNT(*) AS total_pings
        FROM network_ping
        WHERE host_id = %s
          AND timestamp >= now() - interval %s
        """
    )
    params = [host_id, period]

    with connection.cursor() as cursor:
        cursor.execute(sql, params)
        row = cursor.fetchone()

    if not row or row[1] == 0:
        uptime_percentage, total_pings = 0.0, 0
    else:
        uptime_percentage, total_pings = row

    # --- Recalculate uptime for incomplete data ---
    # Parse period to get expected number of minutes
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
    expected_pings = period_minutes

    # If total_pings < expected_pings, treat missing as offline
    if total_pings < expected_pings and expected_pings > 0:
        alive_pings = float(uptime_percentage) * float(total_pings) / 100.0
        uptime_percentage = (alive_pings / expected_pings) * 100
        total_pings = expected_pings

    return uptime_percentage, total_pings, expected_pings

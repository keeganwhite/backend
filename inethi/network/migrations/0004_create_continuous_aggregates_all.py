from django.db import migrations

class Migration(migrations.Migration):
    atomic = False
    dependencies = [
        ('network', '0003_make_ping_hypertable'),
    ]

    operations = [
        # 15-minute aggregate (unchanged)
        migrations.RunSQL(
            sql="""
            CREATE MATERIALIZED VIEW network_ping_aggregate_15m
            WITH (timescaledb.continuous) AS
            SELECT
                time_bucket('15 minutes', timestamp) AS bucket,
                host_id,
                AVG(CASE WHEN is_alive THEN 1.0 ELSE 0.0 END) * 100 AS uptime_percentage,
                COUNT(*) AS total_pings
            FROM network_ping
            GROUP BY bucket, host_id;
            """,
            reverse_sql="DROP MATERIALIZED VIEW IF EXISTS network_ping_aggregate_15m;"
        ),
        migrations.RunSQL(
            sql="""
            SELECT add_continuous_aggregate_policy('network_ping_aggregate_15m',
                start_offset => INTERVAL '1 hour',
                end_offset   => INTERVAL '1 minute',
                schedule_interval => INTERVAL '1 minute'
            );
            """,
            reverse_sql="SELECT remove_continuous_aggregate_policy('network_ping_aggregate_15m');"
        ),

        # 60-minute aggregate
        migrations.RunSQL(
            sql="""
            CREATE MATERIALIZED VIEW network_ping_aggregate_60m
            WITH (timescaledb.continuous) AS
            SELECT
                time_bucket('60 minutes', timestamp) AS bucket,
                host_id,
                AVG(CASE WHEN is_alive THEN 1.0 ELSE 0.0 END) * 100 AS uptime_percentage,
                COUNT(*) AS total_pings
            FROM network_ping
            GROUP BY bucket, host_id;
            """,
            reverse_sql="DROP MATERIALIZED VIEW IF EXISTS network_ping_aggregate_60m;"
        ),
        migrations.RunSQL(
            sql="""
            SELECT add_continuous_aggregate_policy('network_ping_aggregate_60m',
                start_offset => INTERVAL '3 hours',
                end_offset   => INTERVAL '1 minute',
                schedule_interval => INTERVAL '1 minute'
            );
            """,
            reverse_sql="SELECT remove_continuous_aggregate_policy('network_ping_aggregate_60m');"
        ),

        # 6-hour aggregate
        migrations.RunSQL(
            sql="""
            CREATE MATERIALIZED VIEW network_ping_aggregate_6h
            WITH (timescaledb.continuous) AS
            SELECT
                time_bucket('6 hours', timestamp) AS bucket,
                host_id,
                AVG(CASE WHEN is_alive THEN 1.0 ELSE 0.0 END) * 100 AS uptime_percentage,
                COUNT(*) AS total_pings
            FROM network_ping
            GROUP BY bucket, host_id;
            """,
            reverse_sql="DROP MATERIALIZED VIEW IF EXISTS network_ping_aggregate_6h;"
        ),
        migrations.RunSQL(
            sql="""
            SELECT add_continuous_aggregate_policy('network_ping_aggregate_6h',
                start_offset => INTERVAL '13 hours',
                end_offset   => INTERVAL '10 minutes',
                schedule_interval => INTERVAL '30 minutes'
            );
            """,
            reverse_sql="SELECT remove_continuous_aggregate_policy('network_ping_aggregate_6h');"
        ),

        # 12-hour aggregate
        migrations.RunSQL(
            sql="""
            CREATE MATERIALIZED VIEW network_ping_aggregate_12h
            WITH (timescaledb.continuous) AS
            SELECT
                time_bucket('12 hours', timestamp) AS bucket,
                host_id,
                AVG(CASE WHEN is_alive THEN 1.0 ELSE 0.0 END) * 100 AS uptime_percentage,
                COUNT(*) AS total_pings
            FROM network_ping
            GROUP BY bucket, host_id;
            """,
            reverse_sql="DROP MATERIALIZED VIEW IF EXISTS network_ping_aggregate_12h;"
        ),
        migrations.RunSQL(
            sql="""
            SELECT add_continuous_aggregate_policy('network_ping_aggregate_12h',
                start_offset => INTERVAL '25 hours',
                end_offset   => INTERVAL '10 minutes',
                schedule_interval => INTERVAL '1 hour'
            );
            """,
            reverse_sql="SELECT remove_continuous_aggregate_policy('network_ping_aggregate_12h');"
        ),

        # 24-hour aggregate (1 day)
        migrations.RunSQL(
            sql="""
            CREATE MATERIALIZED VIEW network_ping_aggregate_24h
            WITH (timescaledb.continuous) AS
            SELECT
                time_bucket('1 day', timestamp) AS bucket,
                host_id,
                AVG(CASE WHEN is_alive THEN 1.0 ELSE 0.0 END) * 100 AS uptime_percentage,
                COUNT(*) AS total_pings
            FROM network_ping
            GROUP BY bucket, host_id;
            """,
            reverse_sql="DROP MATERIALIZED VIEW IF EXISTS network_ping_aggregate_24h;"
        ),
        migrations.RunSQL(
            sql="""
            SELECT add_continuous_aggregate_policy('network_ping_aggregate_24h',
                start_offset => INTERVAL '3 days',
                end_offset   => INTERVAL '1 hour',
                schedule_interval => INTERVAL '2 hours'
            );
            """,
            reverse_sql="SELECT remove_continuous_aggregate_policy('network_ping_aggregate_24h');"
        ),

        # 7-day aggregate
        migrations.RunSQL(
            sql="""
            CREATE MATERIALIZED VIEW network_ping_aggregate_7d
            WITH (timescaledb.continuous) AS
            SELECT
                time_bucket('7 days', timestamp) AS bucket,
                host_id,
                AVG(CASE WHEN is_alive THEN 1.0 ELSE 0.0 END) * 100 AS uptime_percentage,
                COUNT(*) AS total_pings
            FROM network_ping
            GROUP BY bucket, host_id;
            """,
            reverse_sql="DROP MATERIALIZED VIEW IF EXISTS network_ping_aggregate_7d;"
        ),
        migrations.RunSQL(
            sql="""
            SELECT add_continuous_aggregate_policy('network_ping_aggregate_7d',
                start_offset => INTERVAL '15 days',
                end_offset   => INTERVAL '1 day',
                schedule_interval => INTERVAL '6 hours'
            );
            """,
            reverse_sql="SELECT remove_continuous_aggregate_policy('network_ping_aggregate_7d');"
        ),

        # 30-day aggregate (1 month)
        migrations.RunSQL(
            sql="""
            CREATE MATERIALIZED VIEW network_ping_aggregate_30d
            WITH (timescaledb.continuous) AS
            SELECT
                time_bucket('30 days', timestamp) AS bucket,
                host_id,
                AVG(CASE WHEN is_alive THEN 1.0 ELSE 0.0 END) * 100 AS uptime_percentage,
                COUNT(*) AS total_pings
            FROM network_ping
            GROUP BY bucket, host_id;
            """,
            reverse_sql="DROP MATERIALIZED VIEW IF EXISTS network_ping_aggregate_30d;"
        ),
        migrations.RunSQL(
            sql="""
            SELECT add_continuous_aggregate_policy('network_ping_aggregate_30d',
                start_offset => INTERVAL '61 days',
                end_offset   => INTERVAL '1 day',
                schedule_interval => INTERVAL '12 hours'
            );
            """,
            reverse_sql="SELECT remove_continuous_aggregate_policy('network_ping_aggregate_30d');"
        ),

        # 90-day aggregate
        migrations.RunSQL(
            sql="""
            CREATE MATERIALIZED VIEW network_ping_aggregate_90d
            WITH (timescaledb.continuous) AS
            SELECT
                time_bucket('90 days', timestamp) AS bucket,
                host_id,
                AVG(CASE WHEN is_alive THEN 1.0 ELSE 0.0 END) * 100 AS uptime_percentage,
                COUNT(*) AS total_pings
            FROM network_ping
            GROUP BY bucket, host_id;
            """,
            reverse_sql="DROP MATERIALIZED VIEW IF EXISTS network_ping_aggregate_90d;"
        ),
        migrations.RunSQL(
            sql="""
            SELECT add_continuous_aggregate_policy('network_ping_aggregate_90d',
                start_offset => INTERVAL '181 days',
                end_offset   => INTERVAL '1 day',
                schedule_interval => INTERVAL '1 day'
            );
            """,
            reverse_sql="SELECT remove_continuous_aggregate_policy('network_ping_aggregate_90d');"
        ),

        # 365-day aggregate
        migrations.RunSQL(
            sql="""
            CREATE MATERIALIZED VIEW network_ping_aggregate_365d
            WITH (timescaledb.continuous) AS
            SELECT
                time_bucket('365 days', timestamp) AS bucket,
                host_id,
                AVG(CASE WHEN is_alive THEN 1.0 ELSE 0.0 END) * 100 AS uptime_percentage,
                COUNT(*) AS total_pings
            FROM network_ping
            GROUP BY bucket, host_id;
            """,
            reverse_sql="DROP MATERIALIZED VIEW IF EXISTS network_ping_aggregate_365d;"
        ),
        migrations.RunSQL(
            sql="""
            SELECT add_continuous_aggregate_policy('network_ping_aggregate_365d',
                start_offset => INTERVAL '731 days',
                end_offset   => INTERVAL '1 day',
                schedule_interval => INTERVAL '7 days'
            );
            """,
            reverse_sql="SELECT remove_continuous_aggregate_policy('network_ping_aggregate_365d');"
        ),
    ]

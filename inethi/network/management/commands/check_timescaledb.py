from django.core.management.base import BaseCommand
from django.db import connection
from django.utils import timezone


class Command(BaseCommand):
    help = 'Check and verify TimescaleDB setup and performance'

    def add_arguments(self, parser):
        parser.add_argument(
            '--check-hypertables',
            action='store_true',
            help='Check if hypertables are properly configured',
        )
        parser.add_argument(
            '--check-aggregates',
            action='store_true',
            help='Check continuous aggregates status',
        )
        parser.add_argument(
            '--check-indexes',
            action='store_true',
            help='Check if indexes are properly created',
        )
        parser.add_argument(
            '--performance-test',
            action='store_true',
            help='Run performance tests on queries',
        )
        parser.add_argument(
            '--all',
            action='store_true',
            help='Run all checks',
        )

    def handle(self, *args, **options):
        if options['all'] or options['check_hypertables']:
            self.check_hypertables()

        if options['all'] or options['check_aggregates']:
            self.check_continuous_aggregates()

        if options['all'] or options['check_indexes']:
            self.check_indexes()

        if options['all'] or options['performance_test']:
            self.performance_test()

    def check_hypertables(self):
        self.stdout.write(self.style.SUCCESS('Checking hypertables...'))

        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT
                    hypertable_name,
                    num_chunks,
                    compression_enabled
                FROM timescaledb_information.hypertables
                WHERE hypertable_name = 'network_ping';
            """)

            results = cursor.fetchall()
            if results:
                for row in results:
                    self.stdout.write(f"Hypertable: {row[0]}")
                    self.stdout.write(f"  Chunks: {row[1]}")
                    self.stdout.write(f"  Compression enabled: {row[2]}")
            else:
                self.stdout.write(
                    self.style.ERROR('No hypertable found for network_ping!')
                )

    def check_continuous_aggregates(self):
        self.stdout.write(self.style.SUCCESS('Checking continuous aggregates...'))

        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT
                    view_name,
                    materialized_only,
                    compression_enabled
                FROM timescaledb_information.continuous_aggregates
                WHERE view_name LIKE 'network_ping_aggregate_%';
            """)

            results = cursor.fetchall()
            if results:
                for row in results:
                    self.stdout.write(f"Continuous aggregate: {row[0]}")
                    self.stdout.write(f"  Materialized only: {row[1]}")
                    self.stdout.write(f"  Compression enabled: {row[2]}")
            else:
                self.stdout.write(
                    self.style.ERROR('No continuous aggregates found!')
                )

    def check_indexes(self):
        self.stdout.write(self.style.SUCCESS('Checking indexes...'))

        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT
                    indexname,
                    indexdef
                FROM pg_indexes
                WHERE tablename = 'network_ping'
                AND indexname LIKE 'idx_network_ping_%';
            """)

            results = cursor.fetchall()
            if results:
                for row in results:
                    self.stdout.write(f"Index: {row[0]}")
                    self.stdout.write(f"  Definition: {row[1]}")
            else:
                self.stdout.write(
                    self.style.ERROR('No TimescaleDB indexes found!')
                )

    def performance_test(self):
        self.stdout.write(self.style.SUCCESS('Running performance tests...'))

        # Test 1: Simple time range query
        self.stdout.write('Test 1: Time range query (last 24 hours)')
        start_time = timezone.now()

        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT COUNT(*)
                FROM network_ping
                WHERE timestamp >= now() - interval '24 hours';
            """)
            count = cursor.fetchone()[0]

        end_time = timezone.now()
        duration = (end_time - start_time).total_seconds()
        self.stdout.write(f"  Result: {count} records in {duration:.3f} seconds")

        # Test 2: Aggregation query
        self.stdout.write('Test 2: Aggregation query (last hour)')
        start_time = timezone.now()

        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT
                    host_id,
                    AVG(CASE WHEN is_alive THEN 1.0 ELSE 0 END) * 100 as uptime
                FROM network_ping
                WHERE timestamp >= now() - interval '1 hour'
                GROUP BY host_id;
            """)
            results = cursor.fetchall()

        end_time = timezone.now()
        duration = (end_time - start_time).total_seconds()
        self.stdout.write(f"  Result: {len(results)} hosts in {duration:.3f} seconds")

        # Test 3: Continuous aggregate query
        self.stdout.write('Test 3: Continuous aggregate query (15m)')
        start_time = timezone.now()

        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT COUNT(*)
                FROM network_ping_aggregate_15m
                WHERE bucket >= now() - interval '24 hours';
            """)
            count = cursor.fetchone()[0]

        end_time = timezone.now()
        duration = (end_time - start_time).total_seconds()
        self.stdout.write(
            f"  Result: {count} aggregated records in {duration:.3f} seconds"
        )

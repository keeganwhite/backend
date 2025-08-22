from django.core.management.base import BaseCommand
from django.db import connection


class Command(BaseCommand):
    help = 'Refresh all continuous aggregates for TimescaleDB'

    def handle(self, *args, **options):
        self.stdout.write(
            self.style.SUCCESS('Refreshing continuous aggregates...')
        )

        # List of all continuous aggregates
        aggregates = [
            'network_ping_aggregate_15m',
            'network_ping_aggregate_60m',
            'network_ping_aggregate_6h',
            'network_ping_aggregate_12h',
            'network_ping_aggregate_24h',
            'network_ping_aggregate_7d',
            'network_ping_aggregate_30d',
            'network_ping_aggregate_90d',
            'network_ping_aggregate_365d',
        ]

        with connection.cursor() as cursor:
            for aggregate in aggregates:
                try:
                    self.stdout.write(f"Refreshing {aggregate}...")
                    cursor.execute(
                        f"CALL refresh_continuous_aggregate('{aggregate}', NULL, NULL);"
                    )
                    self.stdout.write(
                        self.style.SUCCESS(f"✓ {aggregate} refreshed successfully")
                    )
                except Exception as e:
                    self.stdout.write(
                        self.style.WARNING(
                            f"⚠ Could not refresh {aggregate}: {str(e)}"
                        )
                    )

        self.stdout.write(
            self.style.SUCCESS('Continuous aggregates refresh completed!')
        )

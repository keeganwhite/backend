# 0003_make_ping_hypertable.py

from django.db import migrations

class Migration(migrations.Migration):
    atomic = False  # The hypertable conversion must run outside of a transaction.

    dependencies = [
        ('network', '0002_alter_ping_primary_key'),
    ]

    operations = [
        migrations.RunSQL(
            sql="""
                SELECT create_hypertable(
                    'network_ping',
                    'timestamp',
                    if_not_exists => TRUE
                );
            """,
            reverse_sql="""
                SELECT drop_hypertable('network_ping'::regclass);
            """,
        ),
    ]
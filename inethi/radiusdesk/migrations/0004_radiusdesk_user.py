# Generated migration for RadiusDeskUser model

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('radiusdesk', '0003_populate_voucher_profiles'),
    ]

    operations = [
        migrations.CreateModel(
            name='RadiusDeskUser',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('username', models.CharField(help_text='Username in the RadiusDesk instance', max_length=255)),
                ('password', models.CharField(help_text='Password for the RadiusDesk permanent user', max_length=255)),
                ('radiusdesk_id', models.IntegerField(help_text='The permanent user ID from RadiusDesk API')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('profile', models.ForeignKey(blank=True, help_text='The profile assigned to this permanent user', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='radiusdesk_users', to='radiusdesk.radiusdeskprofile')),
                ('radius_desk_instance', models.ForeignKey(help_text='The RadiusDesk instance this user belongs to', on_delete=django.db.models.deletion.CASCADE, related_name='radiusdesk_users', to='radiusdesk.radiusdeskinstance')),
                ('user', models.ForeignKey(help_text='The application user', on_delete=django.db.models.deletion.CASCADE, related_name='radiusdesk_users', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'RadiusDesk User',
                'verbose_name_plural': 'RadiusDesk Users',
                'unique_together': {('user', 'radius_desk_instance')},
            },
        ),
    ]


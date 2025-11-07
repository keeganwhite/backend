# Generated manually

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('radiusdesk', '0007_add_payment_method_to_radiusdesk_profile'),
    ]

    operations = [
        migrations.AddField(
            model_name='radiusdeskprofile',
            name='is_permanent_user_registration',
            field=models.BooleanField(default=False, help_text='If True, this profile is used internally for permanent user registration and should not be returned in profile query endpoints'),
        ),
    ]


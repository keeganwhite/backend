import os
from celery import Celery

# set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'inethi.settings')

app = Celery('inethi')

# Using a string here means the worker doesn't
# have to serialize the configuration object to
# child processes. - namespace='CELERY' means all
# celery-related configuration keys should
# have a `CELERY_` prefix.
app.config_from_object('django.conf:settings',
                       namespace='CELERY')

# Load task modules from all registered Django app configs.
app.autodiscover_tasks()

# # Schedule the ping_hosts task to run every 60 seconds.
# app.conf.beat_schedule = {
#     'ping-every-60-seconds': {
#         'task': 'network.tasks.ping_hosts',
#         'schedule': 60.0,
#     },
# }

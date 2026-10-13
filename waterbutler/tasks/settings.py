import os

from kombu import Queue, Exchange

from waterbutler import settings


config = settings.child('TASKS_CONFIG')

WAIT_TIMEOUT = int(config.get('WAIT_TIMEOUT', 20))
WAIT_INTERVAL = float(config.get('WAIT_INTERVAL', 0.5))
ADHOC_BACKEND_PATH = config.get('ADHOC_BACKEND_PATH', '/tmp')
SYNCHRONOUS_TIMEOUT = int(config.get('SYNCHRONOUS_TIMEOUT', 1800))

broker_url = config.get(
    'BROKER_URL',
    'amqp://{}:{}//'.format(
        os.environ.get('RABBITMQ_PORT_5672_TCP_ADDR', ''),
        os.environ.get('RABBITMQ_PORT_5672_TCP_PORT', ''),
    )
)

task_default_queue = config.get('CELERY_DEFAULT_QUEUE', 'waterbutler')
task_queues = (
    Queue('waterbutler', Exchange('waterbutler'), routing_key='waterbutler'),
)

task_always_eager = config.get_bool('CELERY_ALWAYS_EAGER', False)
result_backend = config.get_nullable('CELERY_RESULT_BACKEND', 'rpc://')
result_persistent = config.get_bool('CELERY_RESULT_PERSISTENT', True)
worker_disable_rate_limits = config.get_bool('CELERY_DISABLE_RATE_LIMITS', True)
result_expires = int(config.get('CELERY_TASK_RESULT_EXPIRES', 60))
task_create_missing_queues = config.get_bool('CELERY_CREATE_MISSING_QUEUES', False)
task_acks_late = True
worker_hijack_root_logger = False
task_eager_propagates = True

# Task arguments and results carry WaterButlerPath and metadata objects, which the
# default JSON serializer cannot encode. Keep the pickle serializer that Celery 3.x
# used by default so the task payload format stays as before.
task_serializer = 'pickle'
result_serializer = 'pickle'
accept_content = ['pickle', 'json']
result_accept_content = ['pickle', 'json']

# Remote control messages (including the hello/reply exchange workers do at startup)
# are serialized with task_serializer, so they are pickle too. Keep them on an exchange
# of our own: other Celery applications sharing this broker accept JSON only, and a
# pickle reply from a WaterButler worker would make their workers fail at startup.
control_exchange = config.get('CELERY_CONTROL_EXCHANGE', 'waterbutler')

imports = [
    'waterbutler.tasks.move',
    'waterbutler.tasks.copy',
]

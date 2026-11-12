from celery.app import backends
from celery_amqp_backend import AMQPBackend

from waterbutler.tasks import settings
from waterbutler.tasks.app import app


def test_default_result_backend_keeps_one_queue_per_task():
    # The rpc backend shares one reply queue per client and leaves results of earlier tasks
    # unacknowledged when it polls for a later one, so RabbitMQ eventually closes the channel.
    assert settings.DEFAULT_RESULT_BACKEND == 'celery_amqp_backend.AMQPBackend://'
    backend_cls, _ = backends.by_url(settings.DEFAULT_RESULT_BACKEND, app.loader)
    assert backend_cls is AMQPBackend

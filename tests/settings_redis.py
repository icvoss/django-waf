"""Django settings for the real-Redis integration leg (#78).

Identical to ``tests.settings`` except ``CACHES["default"]`` points at a
real ``django_redis.cache.RedisCache`` instance instead of ``LocMemCache``.
Selected via pytest-django's ``--ds`` flag so the fast unit suite (which
runs everywhere, including a laptop with no Redis installed) is completely
unaffected: importing this module is the only way ``CACHES`` changes.

``DJANGO_WAF_TEST_REDIS_URL`` lets the CI leg point at whichever host/port
the Redis service container is bound to; it defaults to the conventional
local address so this settings module also works for a developer running
``docker run -p 6379:6379 redis:6.0-alpine`` (or the matching version) by
hand.
"""

import os

from tests.settings import *  # noqa: F401, F403

DJANGO_WAF_TEST_REDIS_URL = os.environ.get("DJANGO_WAF_TEST_REDIS_URL", "redis://localhost:6379/0")

CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": DJANGO_WAF_TEST_REDIS_URL,
    }
}

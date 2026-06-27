"""Signal definitions for django-waf."""

from django.dispatch import Signal

# Fired after a BlockRule or AllowRule is saved or deleted.
# Consumers should invalidate the compiled rule cache.
# Provides: instance, created (for saves) / instance (for deletes)
rule_saved = Signal()

# Fired when the anomaly scorer detects suspicious behaviour from an IP.
# Provides: ip_address, anomaly_type, score, details
anomaly_detected = Signal()

# Fired when a proof-of-work challenge is issued to a client.
# Provides: instance (ChallengeToken), ip_address
challenge_issued = Signal()

# Fired when a client successfully solves a challenge.
# Provides: instance (ChallengeToken), ip_address
challenge_solved = Signal()

# Fired when a challenge expires or the client submits an incorrect solution.
# Provides: instance (ChallengeToken), ip_address, reason
challenge_failed = Signal()

# Fired when a request is blocked by a rule.
# Provides: ip_address, path, rule (BlockRule instance or None), verdict
request_blocked = Signal()

# Fired when a request is throttled by rate limiting.
# Provides: ip_address, path, requests_per_minute
request_throttled = Signal()

# Fired after a successful sync with the collective threat feed.
# Provides: added, updated, removed, duration_ms
feed_synced = Signal()

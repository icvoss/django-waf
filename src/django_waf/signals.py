"""Signal definitions for django-waf."""

from django.dispatch import Signal

# Fired after a BlockRule or AllowRule is saved or deleted.
# Emitted from handlers.py after the compiled rule cache is invalidated.
# Provides: instance, created (for saves) / instance (for deletes)
rule_saved = Signal()

# Fired when an anomaly detector creates a rule for suspicious behaviour.
# Provides: rule (the BlockRule created), anomaly_type, details
# The sender is the rule's model class. The offending IP or CIDR is the
# rule's own pattern, and the evidence that triggered detection is in
# details (and, since 1.9.0, mirrored onto the rule's notes field).
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
# Provides: ip_address, user_agent, path, rule (matched rule UUID or None),
# verdict. The middleware sends the matched rule id, never a loaded
# BlockRule row (same choice as EvaluationResult.matched_rule_id).
request_blocked = Signal()

# Fired when a request is throttled by rate limiting.
# Provides: ip_address, path, window (e.g. '1m', '1s', '5m', 'path'),
# retry_after (seconds until the sliding window ages out, or None)
request_throttled = Signal()

# Fired after a successful sync with the collective threat feed.
# Provides: created, updated, expired, skipped (same keys as sync_feed's
# return dict)
feed_synced = Signal()

"""
Rule engine service for django-waf.

Central decision-making service called by the WAF middleware. Evaluates requests
against the cached rule set and returns a verdict. Evaluation order per BR-EVAL-003.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import socket
from typing import NamedTuple
from uuid import UUID

logger = logging.getLogger("django_waf.rule_engine")


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


class EvaluationResult(NamedTuple):
    """Result of evaluating a request against the WAF rule set."""

    verdict: str
    action: str | None
    matched_rule_id: UUID | None
    matched_rule_type: str  # "" when no rule matched; RequestLog.matched_rule_type is NOT NULL
    anomaly_score: float | None
    # Populated only on THROTTLED verdicts (#30), the true seconds until the
    # sliding window's oldest counted event ages out. None for every other
    # verdict. Defaulted so existing positional/keyword construction sites
    # that predate this field keep working unchanged.
    retry_after: int | None = None


class RuleCache(NamedTuple):
    """In-memory rule cache loaded from Redis."""

    version: int
    allow_rules: list
    block_rules: list
    ua_regex_set: list  # list of (compiled_pattern, rule_dict) tuples


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_RULES_VERSION_KEY = "waf:rules:version"
_RULES_CACHE_KEY = "waf:rules:cache:{version}"
_BLOCKED_IP_KEY = "waf:blocked:{ip}"
# Forward-confirmed rDNS (FCrDNS) verified-verdict cache (#34). Keyed on both
# ip and rdns_pattern_hash: a single IP can legitimately be checked against
# more than one AllowRule's rdns_pattern (e.g. a Googlebot pattern and a
# Bingbot pattern both tried against the same request), and the verdict is a
# function of both. The pattern is hashed (not embedded raw) so the key
# stays a bounded length regardless of pattern content.
_BOT_FCRDNS_KEY = "waf:bot_fcrdns:{ip}:{pattern_hash}"
_STATS_KEY = "waf:stats:today"
_CACHE_TTL = 600  # 10 minutes
# Positive FCrDNS verifications are cached for 24 hours, PTR/forward DNS
# records for legitimate crawler infrastructure change rarely.
_FCRDNS_POSITIVE_CACHE_TTL = 86400

_REBUILD_LOCK_KEY = "waf:rule_cache:lock"
_REBUILD_LOCK_TTL = 5  # seconds
_REBUILD_LOCK_RETRIES = 3
_REBUILD_LOCK_RETRY_DELAY = 0.1  # seconds

# In-process rule cache, avoids Redis GET + JSON parse + regex compilation
# on every request when the rule version hasn't changed.
_process_cache: RuleCache | None = None
_process_cache_version: int = -1

# Compiled-UA-regex memoisation cache (#28), keyed on (pattern, match_type).
# _compile_ua_patterns populates this for every UA rule it compiles as part
# of a rule-cache rebuild; _match_ua consults it before falling back to
# re.search on the raw pattern, and memoises anything it compiles itself
# (e.g. an AllowRule UA pattern, which _compile_ua_patterns does not cover,
# or a call made directly against a rule dict that bypassed the cache
# machinery entirely, as some tests do). This means a given pattern is
# compiled at most once per process regardless of which path first needed
# it, closing the gap where cache.ua_regex_set was built but never read.
_ua_pattern_cache: dict[tuple[str, str], re.Pattern | None] = {}


# ---------------------------------------------------------------------------
# Rule cache management
# ---------------------------------------------------------------------------


def load_rule_cache(redis_client) -> RuleCache:
    """Load the active rule set, using an in-process cache when possible.

    Fast path: one Redis GET for the version integer. If unchanged since
    last call, returns the in-process RuleCache without JSON parse or
    regex compilation. Per BR-UA-004, all UA regex patterns are pre-compiled.

    Args:
        redis_client: Configured Redis client instance.

    Returns:
        RuleCache namedtuple.
    """
    global _process_cache, _process_cache_version  # noqa: PLW0603

    # Get current version, single Redis GET (integer)
    raw_version = redis_client.get(_RULES_VERSION_KEY)
    version = int(raw_version) if raw_version else 0

    # Fast path: in-process cache is current
    if _process_cache is not None and _process_cache_version == version:
        return _process_cache

    # Check Redis JSON cache
    cache_key = _RULES_CACHE_KEY.format(version=version)
    cached = redis_client.get(cache_key)

    if cached:
        try:
            data = json.loads(cached)
            allow_rules = data.get("allow_rules", [])
            block_rules = data.get("block_rules", [])
            ua_regex_set = _compile_ua_patterns(block_rules)
            result = RuleCache(
                version=version,
                allow_rules=allow_rules,
                block_rules=block_rules,
                ua_regex_set=ua_regex_set,
            )
            _process_cache = result
            _process_cache_version = version
            return result
        except (json.JSONDecodeError, KeyError):
            pass  # fall through to rebuild

    # Cache miss or corrupt, rebuild from DB
    result = _rebuild_rule_cache(redis_client, version, cache_key)
    _process_cache = result
    _process_cache_version = version
    return result


def _rebuild_rule_cache(redis_client, version: int, cache_key: str) -> RuleCache:
    """Rebuild the rule cache from the database and store in Redis.

    Acquires a short-lived Redis lock before rebuilding so that concurrent
    worker processes racing on a cache miss (e.g. immediately after the rule
    version bumps) don't all hit the database at once. Retries a few times
    on lock contention, then proceeds without the lock (fail-open) rather
    than blocking indefinitely, a duplicate rebuild is wasted work, not a
    correctness problem.
    """
    lock_acquired = _acquire_rebuild_lock(redis_client)
    try:
        return _rebuild_rule_cache_from_db(redis_client, version, cache_key)
    finally:
        if lock_acquired:
            _release_rebuild_lock(redis_client)


def _acquire_rebuild_lock(redis_client) -> bool:
    """Try to acquire the rule-cache rebuild lock, retrying briefly on contention.

    Returns:
        True if the lock was acquired (caller must release it). False if the
        lock could not be acquired after retrying, the caller proceeds
        without it (fail-open).
    """
    import time

    for attempt in range(_REBUILD_LOCK_RETRIES + 1):
        try:
            acquired = redis_client.set(_REBUILD_LOCK_KEY, "1", nx=True, ex=_REBUILD_LOCK_TTL)
        except Exception:
            logger.warning("django-waf: rule cache lock acquisition failed; proceeding without lock")
            return False

        if acquired:
            return True

        if attempt < _REBUILD_LOCK_RETRIES:
            time.sleep(_REBUILD_LOCK_RETRY_DELAY)

    logger.warning(
        "django-waf: rule cache lock unavailable after %d retries; proceeding fail-open",
        _REBUILD_LOCK_RETRIES,
    )
    return False


def _release_rebuild_lock(redis_client) -> None:
    """Delete the rule-cache rebuild lock."""
    try:
        redis_client.delete(_REBUILD_LOCK_KEY)
    except Exception:
        logger.warning("django-waf: failed to release rule cache lock")


def _rebuild_rule_cache_from_db(redis_client, version: int, cache_key: str) -> RuleCache:
    """Read active rules from the database and store the JSON cache in Redis."""
    from django_waf.models import AllowRule, BlockRule

    block_qs = BlockRule.objects.active().values(
        "id",
        "rule_type",
        "match_type",
        "pattern",
        "action",
        "priority",
        "expires_at",
    )

    block_rules = [
        {
            "id": str(r["id"]),
            "rule_type": r["rule_type"],
            "match_type": r["match_type"],
            "pattern": r["pattern"],
            "action": r["action"],
            "priority": r["priority"],
            "expires_at": r["expires_at"].isoformat() if r["expires_at"] else None,
        }
        for r in block_qs
    ]

    allow_qs = AllowRule.objects.active().values(
        "id",
        "rule_type",
        "match_type",
        "pattern",
        "verify_rdns",
        "rdns_pattern",
        "expires_at",
    )
    allow_rules = [
        {
            "id": str(r["id"]),
            "rule_type": r["rule_type"],
            "match_type": r["match_type"],
            "pattern": r["pattern"],
            "verify_rdns": r["verify_rdns"],
            "rdns_pattern": r["rdns_pattern"],
            "expires_at": r["expires_at"].isoformat() if r["expires_at"] else None,
        }
        for r in allow_qs
    ]

    data = {"allow_rules": allow_rules, "block_rules": block_rules}
    redis_client.setex(cache_key, _CACHE_TTL, json.dumps(data))

    ua_regex_set = _compile_ua_patterns(block_rules)
    return RuleCache(
        version=version,
        allow_rules=allow_rules,
        block_rules=block_rules,
        ua_regex_set=ua_regex_set,
    )


def _compile_ua_patterns(block_rules: list) -> list:
    """Pre-compile UA regex/contains patterns for fast matching.

    Returns list of (compiled_re, rule_dict) for UA-type rules only. Every
    ``regex``-match-type pattern compiled here is also memoised into
    ``_ua_pattern_cache`` (#28), keyed on ``(pattern, "regex")``, so
    ``_match_ua`` finds the same compiled object instead of recompiling it
    on every request.
    """
    compiled = []
    for rule in block_rules:
        if rule["rule_type"] != "ua":
            continue
        pattern = rule["pattern"]
        match_type = rule["match_type"]
        try:
            if match_type == "regex":
                compiled_re = re.compile(pattern, re.IGNORECASE)
                _ua_pattern_cache[(pattern, "regex")] = compiled_re
                compiled.append((compiled_re, rule))
            elif match_type == "contains":
                # Escape and wrap for substring match
                compiled.append((re.compile(re.escape(pattern), re.IGNORECASE), rule))
            elif match_type == "exact":
                compiled.append((re.compile(f"^{re.escape(pattern)}$", re.IGNORECASE), rule))
        except re.error:
            logger.warning("Invalid UA pattern in rule %s: %r", rule["id"], pattern)
            _ua_pattern_cache[(pattern, "regex")] = None
    return compiled


# ---------------------------------------------------------------------------
# Request evaluation
# ---------------------------------------------------------------------------


def evaluate_request(
    ip_address: str,
    user_agent: str,
    path: str,
    method: str,
    redis_client,
    referer: str = "",
    request_meta: dict | None = None,
) -> EvaluationResult:
    """Evaluate a request against the WAF rule set and return a verdict.

    Evaluation order per BR-EVAL-003:
    1. Exempt paths, handled by middleware before calling this function
    2. DJANGO_WAF_ENABLED, handled by middleware before calling this function
    3. Valid waf_pass cookie, handled by middleware before calling this function
    4. AllowRules
    5. Redis blocked-IP cache
    6. BlockRules
    7. Rate limits
    8. UA anomaly score (if IP has >10 recent requests)

    Every point below that would return a CHALLENGED verdict (a rule-driven
    BlockRule challenge, the no-referer challenge, or a score-driven
    challenge) is routed through ``_gate_challenge_or_escalate`` first (#27).
    Without that gate, an IP that keeps ignoring challenges never revisits
    the threshold check that would otherwise auto-block it, because each
    new request returns its own challenge verdict before evaluation ever
    reaches the old end-of-function escalation check.

    The HTTP fingerprint verdict (BR-FP-001) is computed once, up front, and
    threaded into every ``_gate_challenge_or_escalate`` call: escalation
    counts a challenge towards the threshold for a fingerprint-classified
    bot regardless of whether it goes on to solve the proof-of-work, since a
    datacentre CPU solves hashcash almost for free (see
    ``_get_unsolved_challenge_count``).

    Args:
        ip_address: Client IP address string.
        user_agent: Raw User-Agent header string.
        path: Request path (without query string).
        method: HTTP method string.
        redis_client: Configured Redis client instance.

    Returns:
        EvaluationResult namedtuple.
    """
    from django_waf import conf
    from django_waf.enums import RuleAction, Verdict
    from django_waf.services.fingerprint import classify_fingerprint
    from django_waf.services.rate_limiter import check_rate_limit, get_request_count
    from django_waf.services.ua_analyser import score_user_agent

    fingerprint_verdict = classify_fingerprint(user_agent, request_meta or {})

    cache = load_rule_cache(redis_client)

    # Step 4: Evaluate AllowRules
    allow_result = _check_allow_rules(ip_address, user_agent, cache, redis_client)
    if allow_result is not None:
        matched_id, _ = allow_result
        return EvaluationResult(
            verdict=Verdict.PASSED,
            action=None,
            matched_rule_id=UUID(matched_id),
            matched_rule_type="allow",
            anomaly_score=None,
        )

    # Step 5: Redis blocked-IP fast-path (BR-EVAL-005)
    blocked_key = _BLOCKED_IP_KEY.format(ip=ip_address)
    cached_value = redis_client.get(blocked_key)
    if cached_value:
        # Cache value is the originally-matched rule_id (when known) so
        # fast-path hits get attributed back to the rule. Legacy "1"
        # entries (written by pre-0.10.6 code) carry no attribution.
        rule_id_str = cached_value.decode() if isinstance(cached_value, bytes) else cached_value
        matched_rule_id = None
        if rule_id_str and rule_id_str != "1":
            try:
                matched_rule_id = UUID(rule_id_str)
                _record_rule_hit(rule_id_str, redis_client)
            except ValueError:
                # Malformed cache value, log nothing, still block.
                pass
        return EvaluationResult(
            verdict=Verdict.BLOCKED,
            action=RuleAction.BLOCK,
            matched_rule_id=matched_rule_id,
            matched_rule_type="block" if matched_rule_id else "",
            anomaly_score=None,
        )

    # Step 6: Evaluate BlockRules
    block_result = _check_block_rules(ip_address, user_agent, cache, redis_client)
    if block_result is not None:
        matched_id, rule = block_result
        action = rule["action"]
        verdict = _action_to_verdict(action)
        block_eval_result = EvaluationResult(
            verdict=verdict,
            action=action,
            matched_rule_id=UUID(matched_id),
            matched_rule_type="block",
            anomaly_score=None,
        )
        if verdict == Verdict.CHALLENGED:
            return _gate_challenge_or_escalate(ip_address, redis_client, block_eval_result, fingerprint_verdict)
        return block_eval_result

    # Step 7: Rate limits
    rate_result = check_rate_limit(ip_address, redis_client, path=path)
    if rate_result.exceeded:
        return EvaluationResult(
            verdict=Verdict.THROTTLED,
            action=RuleAction.THROTTLE,
            matched_rule_id=None,
            matched_rule_type="",
            anomaly_score=None,
            retry_after=rate_result.retry_after,
        )

    # Step 8: No-referer challenge (moved from middleware for proper logging)
    if conf.DJANGO_WAF_CHALLENGE_NO_REFERER and not referer:
        exempt = any(path == p or path.startswith(p) for p in conf.DJANGO_WAF_NO_REFERER_EXEMPT_PATHS)
        if not exempt:
            return _gate_challenge_or_escalate(
                ip_address,
                redis_client,
                EvaluationResult(
                    verdict=Verdict.CHALLENGED,
                    action=RuleAction.CHALLENGE,
                    matched_rule_id=None,
                    matched_rule_type="",
                    anomaly_score=None,
                ),
                fingerprint_verdict,
            )

    # Step 9: Path scoring, always evaluated (no volume threshold).
    path_score = _score_path(path)

    # Step 10: HTTP fingerprint scoring, always evaluated.
    # Detects bots claiming to be browsers but missing expected headers.
    fp_score = 0.0
    if request_meta:
        from django_waf.services.fingerprint import (
            compute_fingerprint,
            is_known_fingerprint,
            score_fingerprint_mismatch,
        )

        fp_hash = compute_fingerprint(request_meta)
        # Skip scoring if this fingerprint is known-good (from solved challenges)
        if not is_known_fingerprint(fp_hash, redis_client):
            fp_score = score_fingerprint_mismatch(user_agent, request_meta)

    # Step 11: UA anomaly scoring, only if IP has >10 recent requests.
    ua_score = 0.0
    recent_count = get_request_count(ip_address, "5m", redis_client)
    if recent_count > 10:
        ua_score = score_user_agent(user_agent)

    total_score = ua_score + path_score + fp_score
    if total_score > 0:
        verdict, action = _score_to_verdict(total_score)
        if verdict == Verdict.CHALLENGED:
            return _gate_challenge_or_escalate(
                ip_address,
                redis_client,
                EvaluationResult(
                    verdict=verdict,
                    action=action,
                    matched_rule_id=None,
                    matched_rule_type="",
                    anomaly_score=total_score,
                ),
                fingerprint_verdict,
            )
        return EvaluationResult(
            verdict=verdict,
            action=action,
            matched_rule_id=None,
            matched_rule_type="",
            anomaly_score=total_score,
        )

    return EvaluationResult(
        verdict=Verdict.ALLOWED,
        action=None,
        matched_rule_id=None,
        matched_rule_type="",
        anomaly_score=None,
    )


# ---------------------------------------------------------------------------
# Internal matching helpers
# ---------------------------------------------------------------------------


def _is_cached_rule_expired(rule: dict) -> bool:
    """Return True if a cached rule dict's expires_at has passed.

    The rule cache can lag the database by up to _CACHE_TTL seconds (or
    longer if expire_rules hasn't run yet), so a rule that expired after
    the cache was built must still be rejected at match time rather than
    waiting for the next cache rebuild (#25).
    """
    expires_at = rule.get("expires_at")
    if not expires_at:
        return False

    from datetime import datetime

    from django.utils import timezone

    expiry = datetime.fromisoformat(expires_at)
    return expiry <= timezone.now()


def _check_allow_rules(
    ip_address: str,
    user_agent: str,
    cache: RuleCache,
    redis_client,
) -> tuple[str, dict] | None:
    """Return (rule_id, rule_dict) if an AllowRule matches, else None."""
    for rule in cache.allow_rules:
        if _is_cached_rule_expired(rule):
            continue  # expired since the cache was built (#25), not a match
        if _rule_matches(rule, ip_address, user_agent):
            if (
                rule.get("verify_rdns")
                and rule.get("rdns_pattern")
                and not _verify_rdns(ip_address, rule["rdns_pattern"], redis_client)
            ):
                continue  # rDNS check failed, treat as no match (BR-EVAL-004)
            return rule["id"], rule
    return None


def _check_block_rules(
    ip_address: str,
    user_agent: str,
    cache: RuleCache,
    redis_client=None,
) -> tuple[str, dict] | None:
    """Return (rule_id, rule_dict) for the first matching BlockRule (by priority), else None.

    If redis_client is provided, increments a hit counter for the matched rule
    (flushed to DB by the update_rule_hit_counts task).
    """
    for rule in cache.block_rules:
        if _is_cached_rule_expired(rule):
            continue  # expired since the cache was built (#25), not a match
        if _rule_matches(rule, ip_address, user_agent):
            if redis_client is not None:
                _record_rule_hit(rule["id"], redis_client)
            return rule["id"], rule
    return None


def _record_rule_hit(rule_id: str, redis_client) -> None:
    """Increment the Redis hit counter for a block rule.

    This is the producer half of the counter ``flush_rule_hit_counts``
    (tasks.py) reads and zeroes every five minutes. Fail-open is correct
    here (BR-EVAL-007: a lost hit count must never turn into a blocked
    request), but a silent failure is more severe than most fail-open paths
    in this package: every subsequent read of this rule's hit count reads
    as zero, which is indistinguishable from the rule never matching at
    all, and an operator auditing "unused" rules by hit count would delete
    a rule that is, in fact, actively blocking traffic. WARNING, not
    ERROR: a transient Redis outage here is the same class of event
    redis_client.get_redis_client already logs at WARNING elsewhere, not a
    boot-time misconfiguration.
    """
    try:
        key = f"waf:rule_hits:{rule_id}"
        redis_client.incr(key)
        redis_client.expire(key, 86400 * 2)  # TTL: 2 days
    except Exception:
        logger.warning("django-waf: failed to record hit for rule %s, hit count will under-report", rule_id)


def _rule_matches(rule: dict, ip_address: str, user_agent: str) -> bool:
    """Determine whether a rule matches the given IP and/or UA."""
    rule_type = rule["rule_type"]
    match_type = rule["match_type"]
    pattern = rule["pattern"]

    if rule_type == "ua":
        return _match_ua(user_agent, pattern, match_type)

    if rule_type == "ip":
        return _match_ip(ip_address, pattern, match_type)

    if rule_type == "cidr":
        return _match_cidr(ip_address, pattern)

    if rule_type == "composite":
        # Both UA and IP/CIDR must match (BR-EVAL-007).
        # Pattern format: "ua_pattern||ip_or_cidr_pattern"
        # e.g. "Go-http-client||10.0.0.0/8" or "python-requests||203.0.113.42"
        if "||" in pattern:
            ua_part, ip_part = pattern.split("||", 1)
            ua_match = _match_ua(user_agent, ua_part.strip(), match_type)
            ip_match = _match_ip(ip_address, ip_part.strip(), match_type) or _match_cidr(ip_address, ip_part.strip())
            return ua_match and ip_match
        # Legacy single-pattern fallback, unlikely to match correctly
        return False

    return False


def _match_ua(user_agent: str, pattern: str, match_type: str) -> bool:
    """Match a user agent string against a pattern.

    For ``match_type == "regex"``, uses the compiled-pattern memoisation
    cache (#28) instead of calling ``re.search`` on the raw string on every
    invocation: a pattern compiled once (either here or by
    ``_compile_ua_patterns`` during a rule-cache rebuild) is looked up by
    ``(pattern, "regex")`` and reused for the lifetime of the process,
    rather than being recompiled on every request that carries a matching
    rule.
    """
    if match_type == "exact":
        return user_agent == pattern
    if match_type == "contains":
        return pattern.lower() in user_agent.lower()
    if match_type == "regex":
        compiled = _get_compiled_ua_regex(pattern)
        if compiled is None:
            return False
        return bool(compiled.search(user_agent))
    return False


def _get_compiled_ua_regex(pattern: str) -> re.Pattern | None:
    """Return the compiled regex for ``pattern``, compiling and memoising on miss.

    Returns ``None`` if the pattern is invalid (mirrors the previous
    behaviour of ``_match_ua`` swallowing ``re.error`` and returning False).
    A cache hit avoids recompiling the same pattern on every request; a
    cache miss compiles once and stores the result (including a negative
    result for an invalid pattern) so subsequent calls never recompile.
    """
    cache_key = (pattern, "regex")
    if cache_key in _ua_pattern_cache:
        return _ua_pattern_cache[cache_key]

    try:
        compiled = re.compile(pattern, re.IGNORECASE)
    except re.error:
        _ua_pattern_cache[cache_key] = None
        return None

    _ua_pattern_cache[cache_key] = compiled
    return compiled


def _match_ip(ip_address: str, pattern: str, match_type: str) -> bool:
    """Match an IP address string against a pattern (exact)."""
    if match_type in ("exact", "cidr"):
        return ip_address == pattern
    return False


def _match_cidr(ip_address: str, cidr_pattern: str) -> bool:
    """Check whether an IP address falls within a CIDR range."""
    try:
        return ipaddress.ip_address(ip_address) in ipaddress.ip_network(cidr_pattern, strict=False)
    except ValueError:
        return False


def _verify_rdns(ip_address: str, rdns_pattern: str, redis_client) -> bool:
    """Verify the IP via forward-confirmed reverse DNS (FCrDNS) (#34).

    A bare PTR (reverse-DNS) lookup is not proof of identity: an attacker
    who controls the PTR record of their own IP (any cloud VM with settable
    rDNS) can make ``socket.gethostbyaddr`` return a hostname that matches
    ``rdns_pattern`` (e.g. anything ending ``.googlebot.com``) without being
    Google at all. Forward confirmation closes that gap: after the PTR
    hostname matches the pattern, the hostname is forward-resolved
    (``socket.getaddrinfo``, both address families) and the check only
    passes if the *original* IP appears among the forward-resolved
    addresses, proving whoever controls ``rdns_pattern``'s DNS zone (e.g.
    Google, for ``*.googlebot.com``) also vouches for this IP, not just
    whoever controls the PTR record of the IP itself.

    The final verified verdict (not the raw hostname) is cached in Redis,
    keyed on both ip and rdns_pattern (hashed) since a single IP can
    legitimately be checked against more than one AllowRule's pattern.
    Positive verdicts cache for 24 hours; negative verdicts (pattern
    mismatch, forward-resolution mismatch, or any DNS error on either
    lookup) cache for DJANGO_WAF_RDNS_FAILURE_CACHE_TTL (default 5 minutes)
    so a transient resolver outage does not suppress a legitimate crawler's
    AllowRule match for a full day per IP.

    Any DNS error, on the reverse lookup or the forward lookup, fails
    closed (returns False).

    Args:
        ip_address: IP to reverse-lookup and confirm.
        rdns_pattern: Regex the resolved PTR hostname must match.
        redis_client: Redis client for caching.

    Returns:
        True only if the PTR hostname matches rdns_pattern AND the
        hostname's forward DNS resolution includes ip_address.
    """
    from django_waf import conf

    cache_key = _fcrdns_cache_key(ip_address, rdns_pattern)
    cached_verdict = redis_client.get(cache_key)
    if cached_verdict is not None:
        verdict_str = cached_verdict if isinstance(cached_verdict, str) else cached_verdict.decode()
        return verdict_str == "1"

    verdict = _resolve_and_confirm_rdns(ip_address, rdns_pattern)

    ttl = _FCRDNS_POSITIVE_CACHE_TTL if verdict else conf.DJANGO_WAF_RDNS_FAILURE_CACHE_TTL
    redis_client.setex(cache_key, ttl, "1" if verdict else "0")
    return verdict


def _fcrdns_cache_key(ip_address: str, rdns_pattern: str) -> str:
    """Return the FCrDNS verdict cache key for an (ip, pattern) pair.

    Not a security use, just a stable, bounded-length key fragment derived
    from the pattern string, mirroring the same hashing approach used for
    per-path rate-limit keys in rate_limiter.py.
    """
    import hashlib

    pattern_hash = hashlib.sha1(rdns_pattern.encode(), usedforsecurity=False).hexdigest()[:12]
    return _BOT_FCRDNS_KEY.format(ip=ip_address, pattern_hash=pattern_hash)


def _resolve_and_confirm_rdns(ip_address: str, rdns_pattern: str) -> bool:
    """Perform the actual reverse + forward DNS resolution and comparison.

    No caching here, callers (``_verify_rdns``) own the cache. Split out
    so the two concerns (DNS resolution vs. verdict caching) can be tested
    independently.
    """
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
    except (socket.herror, socket.gaierror, OSError):
        return False  # reverse lookup failed, fail closed

    if not hostname:
        return False

    try:
        if not re.search(rdns_pattern, hostname, re.IGNORECASE):
            return False
    except re.error:
        return False

    try:
        forward_addresses = {info[4][0] for info in socket.getaddrinfo(hostname, None)}
    except (socket.gaierror, OSError):
        return False  # forward lookup failed, fail closed

    try:
        target = ipaddress.ip_address(ip_address)
    except ValueError:
        return False

    for candidate in forward_addresses:
        try:
            if ipaddress.ip_address(candidate) == target:
                return True
        except ValueError:
            continue

    return False


def _action_to_verdict(action: str) -> str:
    """Map a RuleAction value to the corresponding Verdict value.

    ``action`` is typed as ``str`` rather than ``RuleAction`` because callers
    genuinely pass a plain string here: the value comes from a cached rule
    dict built from serialised data (see ``_check_block_rules``), not a live
    model instance, and an unrecognised value is a legitimate input this
    function must handle by falling back to ``Verdict.BLOCKED`` rather than
    raising (proven by test_action_to_verdict_unknown_defaults_to_blocked).
    The mapping itself is keyed by ``RuleAction`` value, so the lookup is
    done against ``.value`` strings rather than widening the dict to accept
    arbitrary strings as valid ``RuleAction`` keys.
    """
    from django_waf.enums import RuleAction, Verdict

    mapping = {
        RuleAction.BLOCK.value: Verdict.BLOCKED,
        RuleAction.CHALLENGE.value: Verdict.CHALLENGED,
        RuleAction.THROTTLE.value: Verdict.THROTTLED,
        RuleAction.LOG_ONLY.value: Verdict.LOGGED,
    }
    return mapping.get(action, Verdict.BLOCKED)


def _score_to_verdict(score: float) -> tuple[str, str | None]:
    """Map an anomaly score to (verdict, action).

    Thresholds are configurable via settings:
      DJANGO_WAF_SCORE_THRESHOLD_BLOCK (default 7.0)
      DJANGO_WAF_SCORE_THRESHOLD_CHALLENGE (default 5.0)
      DJANGO_WAF_SCORE_THRESHOLD_LOG (default 3.0)
    """
    from django_waf import conf
    from django_waf.enums import RuleAction, Verdict

    if score >= conf.DJANGO_WAF_SCORE_THRESHOLD_BLOCK:
        return Verdict.BLOCKED, RuleAction.BLOCK
    if score >= conf.DJANGO_WAF_SCORE_THRESHOLD_CHALLENGE:
        return Verdict.CHALLENGED, RuleAction.CHALLENGE
    if score >= conf.DJANGO_WAF_SCORE_THRESHOLD_LOG:
        return Verdict.LOGGED, RuleAction.LOG_ONLY
    return Verdict.ALLOWED, None


def _score_path(path: str) -> float:
    """Return anomaly score contribution from suspicious path patterns.

    Accumulates score for each matching pattern (multiple matches = higher
    confidence). Capped at 10.0.
    """
    import re

    from django_waf import conf

    score = 0.0
    for pattern in conf.DJANGO_WAF_SUSPICIOUS_PATH_PATTERNS:
        try:
            if re.search(pattern, path, re.IGNORECASE):
                score += conf.DJANGO_WAF_SUSPICIOUS_PATH_SCORE
                if score >= 10.0:
                    return 10.0
        except re.error:
            continue
    return score


def _gate_challenge_or_escalate(
    ip_address: str,
    redis_client,
    challenge_result: EvaluationResult,
    fingerprint_verdict: str = "",
) -> EvaluationResult:
    """Single escalation gate, called before returning ANY challenge verdict.

    Fixes #27: evaluate_request has three places that can produce a
    CHALLENGED verdict (a rule-driven BlockRule challenge, the no-referer
    challenge, and a score-driven challenge). The escalation check used to
    live only at the very end of evaluate_request, after all three of
    those early returns, so a repeatedly-challenged IP never reached it
    and auto-block-on-ignored-challenges was dead code. Routing every
    challenge verdict through this one gate first makes escalation reachable
    regardless of which path produced the challenge.

    If the IP's challenge count has reached
    DJANGO_WAF_CHALLENGE_ESCALATION_THRESHOLD, creates (or reuses) a
    persistent auto BlockRule and returns a BLOCKED verdict referencing it
    instead of the challenge verdict. Otherwise returns challenge_result
    unchanged.

    Args:
        ip_address: Client IP address string.
        redis_client: Configured Redis client instance.
        challenge_result: The CHALLENGED EvaluationResult that would
            otherwise be returned.
        fingerprint_verdict: BR-FP-001's classify_fingerprint result for
            this request (browser, bot, suspicious, or unknown). Passed
            through to _get_unsolved_challenge_count so a
            fingerprint-classified bot's solved challenges still count
            towards escalation (see that function's docstring).

    Returns:
        A BLOCKED EvaluationResult when escalation triggers, else
        challenge_result unchanged.
    """
    from django_waf import conf
    from django_waf.enums import RuleAction, Verdict

    challenged_count = _get_unsolved_challenge_count(ip_address, redis_client, fingerprint_verdict)
    if challenged_count < conf.DJANGO_WAF_CHALLENGE_ESCALATION_THRESHOLD:
        return challenge_result

    escalation_rule = _create_escalation_rule(ip_address)
    record_block_verdict(
        ip_address,
        redis_client,
        ttl=conf.DJANGO_WAF_ESCALATION_BLOCK_TTL,
        rule_id=str(escalation_rule.id) if escalation_rule else None,
    )
    return EvaluationResult(
        verdict=Verdict.BLOCKED,
        action=RuleAction.BLOCK,
        matched_rule_id=None,
        matched_rule_type="",
        anomaly_score=None,
    )


def _get_unsolved_challenge_count(ip_address: str, redis_client, fingerprint_verdict: str = "") -> int:
    """Count recent challenges for an IP towards the escalation threshold.

    Uses Redis counter waf:challenged:{ip} incremented by the middleware on
    each CHALLENGED verdict. Whether a solved challenge clears that counter
    depends on ``fingerprint_verdict`` (BR-FP-001, computed by
    evaluate_request from the request's own headers, independently of
    whether the challenge gets solved):

    - When fingerprint_verdict == "bot", the count is returned regardless
      of the Redis waf:solved:{ip} flag. A JS-executing botnet solves the
      SHA-256 proof-of-work at negligible cost on datacentre CPUs (BR-CHAL-002
      assumes solving proves a human/real browser, which a bot with a
      correct hashcash implementation trivially defeats), so treating
      "solved" as "legitimate" let a botnet accumulate challenged verdicts
      forever without ever reaching the block threshold. Verified in
      production: ~37,700 events from a rotating-UA datacentre botnet
      produced 3,044 challenged verdicts and zero blocks, because every one
      of those requests both matched fingerprint_verdict == "bot" and
      solved the challenge.
    - For every other fingerprint_verdict, a solved challenge still clears
      the counter to 0 exactly as before this fix: a genuine browser that
      solves a challenge is not penalised for having been challenged.

    Returning 0 means "this IP has never been challenged", the same value
    a genuinely fresh IP produces. A Redis failure here is therefore not a
    neutral fail-open: it silently disables challenge escalation entirely
    for the affected IP for as long as the failure persists, since
    ``_gate_challenge_or_escalate`` never sees a count reach
    DJANGO_WAF_CHALLENGE_ESCALATION_THRESHOLD. A bot farm failing every
    challenge would simply never escalate to a block. Fail-open is still
    correct (BR-EVAL-007: a Redis outage must not turn every challenge into
    a block), but it must be loud, not indistinguishable from the fresh-IP
    case.
    """
    try:
        key = f"waf:challenged:{ip_address}"
        count = redis_client.get(key)
        if not count:
            return 0
        count = int(count)

        if fingerprint_verdict == "bot":
            return count

        # Fast path: check Redis solved flag first
        solved_key = f"waf:solved:{ip_address}"
        if redis_client.get(solved_key):
            redis_client.delete(key)
            return 0

        return count
    except Exception:
        logger.warning(
            "django-waf: failed to read unsolved-challenge count for %s, "
            "challenge escalation is disabled for this IP until Redis recovers",
            ip_address,
        )
        return 0


def _create_escalation_rule(ip_address: str):  # -> BlockRule | None
    # Returns the created/updated BlockRule so callers can attribute the
    # fast-path cache entry to its id (see record_block_verdict). Returns
    # None on failure; callers should treat that as "block but unknown rule".
    """Create a persistent auto BlockRule for an escalated IP.

    Routes through anomaly_detector._get_or_create_auto_rule (the same
    guarded path detect_ua_rotation/detect_subnet_burst/detect_cloud_spray/
    detect_challenge_farms use) rather than calling
    BlockRule.objects.update_or_create directly. Escalation used to bypass
    that guard entirely: an operator's REJECTED review decision on a
    (rule_type=ip, pattern, source=AUTO, action=block) row could be
    silently resurrected as an active block the next time the same IP hit
    the escalation threshold, exactly the enforce-then-review order
    BR-ANOM-007's quarantine machinery exists to prevent. Concurrent
    escalations and pre-existing duplicate rows are handled by
    _get_or_create_auto_rule itself, so this function no longer needs its
    own dedup/retry logic.

    The rule is picked up by the nginx blocklist generator on its next run.
    Import of anomaly_detector is deferred to the function body: rule_engine
    is imported during middleware request evaluation, and anomaly_detector
    imports from models/conf at module scope, so a module-level import here
    would risk a circular import against anomaly_detector's own callers.
    """
    from datetime import timedelta

    from django.utils import timezone

    from django_waf import conf
    from django_waf.enums import RuleAction, RuleType
    from django_waf.services.anomaly_detector import _get_or_create_auto_rule

    try:
        rule, _created = _get_or_create_auto_rule(
            name=f"Auto: escalated from repeated challenges ({ip_address})",
            rule_type=RuleType.IP,
            match_type="exact",
            pattern=ip_address,
            action=RuleAction.BLOCK,
            expiry=timezone.now() + timedelta(seconds=conf.DJANGO_WAF_ESCALATION_BLOCK_TTL),
            detector_name="challenge_escalation",
        )
        return rule
    except Exception:
        logger.exception("django-waf: failed to create escalation rule for %s", ip_address)
        return None


# ---------------------------------------------------------------------------
# Fast-path block verdict recording
# ---------------------------------------------------------------------------


def record_block_verdict(
    ip_address: str,
    redis_client,
    ttl: int = 300,
    rule_id: str | None = None,
) -> None:
    """Write the blocked-IP cache entry for fast-path rejection on subsequent requests.

    Also increments the daily stats counter.

    Per BR-EVAL-005.

    Args:
        ip_address: The blocked IP address.
        redis_client: Configured Redis client instance.
        ttl: Cache TTL in seconds (default 300 = 5 minutes).
        rule_id: Optional matched rule id. Stored as the cache value so the
            fast-path can attribute subsequent hits to the original rule
            via ``_record_rule_hit``. Defaults to a sentinel string when
            unknown; cache reads tolerate the legacy ``"1"`` value as the
            same sentinel.
    """
    blocked_key = _BLOCKED_IP_KEY.format(ip=ip_address)
    value = str(rule_id) if rule_id else "1"
    redis_client.setex(blocked_key, ttl, value)
    redis_client.hincrby(_STATS_KEY, "blocked", 1)

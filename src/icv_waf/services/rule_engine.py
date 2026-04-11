"""
Rule engine service for icv-waf.

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

logger = logging.getLogger("icv_waf.rule_engine")


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
_BOT_RDNS_KEY = "waf:bot_rdns:{ip}"
_STATS_KEY = "waf:stats:today"
_CACHE_TTL = 600  # 10 minutes

# In-process rule cache — avoids Redis GET + JSON parse + regex compilation
# on every request when the rule version hasn't changed.
_process_cache: RuleCache | None = None
_process_cache_version: int = -1


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

    # Get current version — single Redis GET (integer)
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

    # Cache miss or corrupt — rebuild from DB
    result = _rebuild_rule_cache(redis_client, version, cache_key)
    _process_cache = result
    _process_cache_version = version
    return result


def _rebuild_rule_cache(redis_client, version: int, cache_key: str) -> RuleCache:
    """Rebuild the rule cache from the database and store in Redis."""
    from icv_waf.models import AllowRule, BlockRule

    block_qs = BlockRule.objects.active().values(
        "id",
        "rule_type",
        "match_type",
        "pattern",
        "action",
        "priority",
    )

    block_rules = [
        {
            "id": str(r["id"]),
            "rule_type": r["rule_type"],
            "match_type": r["match_type"],
            "pattern": r["pattern"],
            "action": r["action"],
            "priority": r["priority"],
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
    )
    allow_rules = [
        {
            "id": str(r["id"]),
            "rule_type": r["rule_type"],
            "match_type": r["match_type"],
            "pattern": r["pattern"],
            "verify_rdns": r["verify_rdns"],
            "rdns_pattern": r["rdns_pattern"],
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

    Returns list of (compiled_re, rule_dict) for UA-type rules only.
    """
    compiled = []
    for rule in block_rules:
        if rule["rule_type"] != "ua":
            continue
        pattern = rule["pattern"]
        match_type = rule["match_type"]
        try:
            if match_type == "regex":
                compiled.append((re.compile(pattern, re.IGNORECASE), rule))
            elif match_type == "contains":
                # Escape and wrap for substring match
                compiled.append((re.compile(re.escape(pattern), re.IGNORECASE), rule))
            elif match_type == "exact":
                compiled.append((re.compile(f"^{re.escape(pattern)}$", re.IGNORECASE), rule))
        except re.error:
            logger.warning("Invalid UA pattern in rule %s: %r", rule["id"], pattern)
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
    1. Exempt paths — handled by middleware before calling this function
    2. ICV_WAF_ENABLED — handled by middleware before calling this function
    3. Valid waf_pass cookie — handled by middleware before calling this function
    4. AllowRules
    5. Redis blocked-IP cache
    6. BlockRules
    7. Rate limits
    8. UA anomaly score (if IP has >10 recent requests)

    Args:
        ip_address: Client IP address string.
        user_agent: Raw User-Agent header string.
        path: Request path (without query string).
        method: HTTP method string.
        redis_client: Configured Redis client instance.

    Returns:
        EvaluationResult namedtuple.
    """
    from icv_waf import conf
    from icv_waf.enums import RuleAction, Verdict
    from icv_waf.services.rate_limiter import check_rate_limit, get_request_count
    from icv_waf.services.ua_analyser import score_user_agent

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
    if redis_client.get(blocked_key):
        return EvaluationResult(
            verdict=Verdict.BLOCKED,
            action=RuleAction.BLOCK,
            matched_rule_id=None,
            matched_rule_type="",
            anomaly_score=None,
        )

    # Step 6: Evaluate BlockRules
    block_result = _check_block_rules(ip_address, user_agent, cache, redis_client)
    if block_result is not None:
        matched_id, rule = block_result
        action = rule["action"]
        verdict = _action_to_verdict(action)
        return EvaluationResult(
            verdict=verdict,
            action=action,
            matched_rule_id=UUID(matched_id),
            matched_rule_type="block",
            anomaly_score=None,
        )

    # Step 7: Rate limits
    rate_result = check_rate_limit(ip_address, redis_client)
    if rate_result.exceeded:
        return EvaluationResult(
            verdict=Verdict.THROTTLED,
            action=RuleAction.THROTTLE,
            matched_rule_id=None,
            matched_rule_type="",
            anomaly_score=None,
        )

    # Step 8: No-referer challenge (moved from middleware for proper logging)
    if conf.ICV_WAF_CHALLENGE_NO_REFERER and not referer:
        exempt = any(path == p or path.startswith(p) for p in conf.ICV_WAF_NO_REFERER_EXEMPT_PATHS)
        if not exempt:
            return EvaluationResult(
                verdict=Verdict.CHALLENGED,
                action=RuleAction.CHALLENGE,
                matched_rule_id=None,
                matched_rule_type="",
                anomaly_score=None,
            )

    # Step 9: Path scoring — always evaluated (no volume threshold).
    path_score = _score_path(path)

    # Step 10: HTTP fingerprint scoring — always evaluated.
    # Detects bots claiming to be browsers but missing expected headers.
    fp_score = 0.0
    if request_meta:
        from icv_waf.services.fingerprint import (
            compute_fingerprint,
            is_known_fingerprint,
            score_fingerprint_mismatch,
        )

        fp_hash = compute_fingerprint(request_meta)
        # Skip scoring if this fingerprint is known-good (from solved challenges)
        if not is_known_fingerprint(fp_hash, redis_client):
            fp_score = score_fingerprint_mismatch(user_agent, request_meta)

    # Step 11: UA anomaly scoring — only if IP has >10 recent requests.
    ua_score = 0.0
    recent_count = get_request_count(ip_address, "5m", redis_client)
    if recent_count > 10:
        ua_score = score_user_agent(user_agent)

    total_score = ua_score + path_score + fp_score
    if total_score > 0:
        verdict, action = _score_to_verdict(total_score)
        if verdict != Verdict.ALLOWED:
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
            anomaly_score=total_score,
        )

    # Step 10: Challenge escalation — auto-block IPs that ignore challenges.
    # Creates a persistent auto BlockRule + Redis fast-path with configurable TTL.
    challenged_count = _get_unsolved_challenge_count(ip_address, redis_client)
    if challenged_count >= conf.ICV_WAF_CHALLENGE_ESCALATION_THRESHOLD:
        record_block_verdict(ip_address, redis_client, ttl=conf.ICV_WAF_ESCALATION_BLOCK_TTL)
        _create_escalation_rule(ip_address)
        return EvaluationResult(
            verdict=Verdict.BLOCKED,
            action=RuleAction.BLOCK,
            matched_rule_id=None,
            matched_rule_type="",
            anomaly_score=None,
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


def _check_allow_rules(
    ip_address: str,
    user_agent: str,
    cache: RuleCache,
    redis_client,
) -> tuple[str, dict] | None:
    """Return (rule_id, rule_dict) if an AllowRule matches, else None."""
    for rule in cache.allow_rules:
        if _rule_matches(rule, ip_address, user_agent):
            if (
                rule.get("verify_rdns")
                and rule.get("rdns_pattern")
                and not _verify_rdns(ip_address, rule["rdns_pattern"], redis_client)
            ):
                continue  # rDNS check failed — treat as no match (BR-EVAL-004)
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
        if _rule_matches(rule, ip_address, user_agent):
            if redis_client is not None:
                _record_rule_hit(rule["id"], redis_client)
            return rule["id"], rule
    return None


def _record_rule_hit(rule_id: str, redis_client) -> None:
    """Increment the Redis hit counter for a block rule."""
    try:
        key = f"waf:rule_hits:{rule_id}"
        redis_client.incr(key)
        redis_client.expire(key, 86400 * 2)  # TTL: 2 days
    except Exception:
        pass


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
        # Legacy single-pattern fallback — unlikely to match correctly
        return False

    return False


def _match_ua(user_agent: str, pattern: str, match_type: str) -> bool:
    """Match a user agent string against a pattern."""
    if match_type == "exact":
        return user_agent == pattern
    if match_type == "contains":
        return pattern.lower() in user_agent.lower()
    if match_type == "regex":
        try:
            return bool(re.search(pattern, user_agent, re.IGNORECASE))
        except re.error:
            return False
    return False


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
    """Verify that the IP's reverse DNS hostname matches rdns_pattern.

    Results are cached in Redis for 24 hours (BR-EVAL-004).

    Args:
        ip_address: IP to reverse-lookup.
        rdns_pattern: Regex the resolved hostname must match.
        redis_client: Redis client for caching.

    Returns:
        True if rDNS resolves and hostname matches the pattern.
    """
    cache_key = _BOT_RDNS_KEY.format(ip=ip_address)
    cached_hostname = redis_client.get(cache_key)

    if cached_hostname is None:
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
        except (socket.herror, socket.gaierror, OSError):
            hostname = ""
        redis_client.setex(cache_key, 86400, hostname)
    else:
        hostname = cached_hostname if isinstance(cached_hostname, str) else cached_hostname.decode()

    if not hostname:
        return False

    try:
        return bool(re.search(rdns_pattern, hostname, re.IGNORECASE))
    except re.error:
        return False


def _action_to_verdict(action: str) -> str:
    """Map a RuleAction value to the corresponding Verdict value."""
    from icv_waf.enums import RuleAction, Verdict

    mapping = {
        RuleAction.BLOCK: Verdict.BLOCKED,
        RuleAction.CHALLENGE: Verdict.CHALLENGED,
        RuleAction.THROTTLE: Verdict.THROTTLED,
        RuleAction.LOG_ONLY: Verdict.LOGGED,
    }
    return mapping.get(action, Verdict.BLOCKED)


def _score_to_verdict(score: float) -> tuple[str, str | None]:
    """Map an anomaly score to (verdict, action).

    Thresholds are configurable via settings:
      ICV_WAF_SCORE_THRESHOLD_BLOCK (default 7.0)
      ICV_WAF_SCORE_THRESHOLD_CHALLENGE (default 5.0)
      ICV_WAF_SCORE_THRESHOLD_LOG (default 3.0)
    """
    from icv_waf import conf
    from icv_waf.enums import RuleAction, Verdict

    if score >= conf.ICV_WAF_SCORE_THRESHOLD_BLOCK:
        return Verdict.BLOCKED, RuleAction.BLOCK
    if score >= conf.ICV_WAF_SCORE_THRESHOLD_CHALLENGE:
        return Verdict.CHALLENGED, RuleAction.CHALLENGE
    if score >= conf.ICV_WAF_SCORE_THRESHOLD_LOG:
        return Verdict.LOGGED, RuleAction.LOG_ONLY
    return Verdict.ALLOWED, None


def _score_path(path: str) -> float:
    """Return anomaly score contribution from suspicious path patterns.

    Accumulates score for each matching pattern (multiple matches = higher
    confidence). Capped at 10.0.
    """
    import re

    from icv_waf import conf

    score = 0.0
    for pattern in conf.ICV_WAF_SUSPICIOUS_PATH_PATTERNS:
        try:
            if re.search(pattern, path, re.IGNORECASE):
                score += conf.ICV_WAF_SUSPICIOUS_PATH_SCORE
                if score >= 10.0:
                    return 10.0
        except re.error:
            continue
    return score


def _get_unsolved_challenge_count(ip_address: str, redis_client) -> int:
    """Count recent challenged verdicts for an IP with no solved ChallengeTokens.

    Uses Redis counter waf:challenged:{ip} incremented by the middleware
    on each CHALLENGED verdict. Checks Redis waf:solved:{ip} flag first
    (set by VerifyView on successful solve), falling back to DB only on miss.
    """
    try:
        key = f"waf:challenged:{ip_address}"
        count = redis_client.get(key)
        if not count:
            return 0
        count = int(count)

        # Fast path: check Redis solved flag first
        solved_key = f"waf:solved:{ip_address}"
        if redis_client.get(solved_key):
            redis_client.delete(key)
            return 0

        return count
    except Exception:
        return 0


def _create_escalation_rule(ip_address: str) -> None:
    """Create a persistent auto BlockRule for an escalated IP.

    Uses update_or_create so concurrent escalations don't duplicate.
    The rule is picked up by the nginx blocklist generator on its next run.
    """
    from datetime import timedelta

    from django.db import transaction
    from django.utils import timezone

    from icv_waf import conf
    from icv_waf.enums import RuleAction, RuleSource, RuleType
    from icv_waf.models import BlockRule

    try:
        with transaction.atomic():
            BlockRule.objects.update_or_create(
                rule_type=RuleType.IP,
                pattern=ip_address,
                source=RuleSource.AUTO,
                action=RuleAction.BLOCK,
                defaults={
                    "name": f"Auto: escalated from unsolved challenges ({ip_address})",
                    "match_type": "exact",
                    "is_active": True,
                    "expires_at": timezone.now() + timedelta(seconds=conf.ICV_WAF_ESCALATION_BLOCK_TTL),
                },
            )
    except Exception:
        logger.exception("icv-waf: failed to create escalation rule for %s", ip_address)


# ---------------------------------------------------------------------------
# Fast-path block verdict recording
# ---------------------------------------------------------------------------


def record_block_verdict(
    ip_address: str,
    redis_client,
    ttl: int = 300,
) -> None:
    """Write the blocked-IP cache entry for fast-path rejection on subsequent requests.

    Also increments the daily stats counter.

    Per BR-EVAL-005.

    Args:
        ip_address: The blocked IP address.
        redis_client: Configured Redis client instance.
        ttl: Cache TTL in seconds (default 300 = 5 minutes).
    """
    blocked_key = _BLOCKED_IP_KEY.format(ip=ip_address)
    redis_client.setex(blocked_key, ttl, "1")
    redis_client.hincrby(_STATS_KEY, "blocked", 1)

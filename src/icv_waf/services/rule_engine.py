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
    matched_rule_type: str | None
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


# ---------------------------------------------------------------------------
# Rule cache management
# ---------------------------------------------------------------------------


def load_rule_cache(redis_client) -> RuleCache:
    """Load the active rule set from Redis cache, rebuilding from DB if stale.

    Per BR-UA-004, all UA regex patterns are pre-compiled into memory.

    Args:
        redis_client: Configured Redis client instance.

    Returns:
        RuleCache namedtuple.
    """
    # Get current version
    raw_version = redis_client.get(_RULES_VERSION_KEY)
    version = int(raw_version) if raw_version else 0

    cache_key = _RULES_CACHE_KEY.format(version=version)
    cached = redis_client.get(cache_key)

    if cached:
        try:
            data = json.loads(cached)
            allow_rules = data.get("allow_rules", [])
            block_rules = data.get("block_rules", [])
            ua_regex_set = _compile_ua_patterns(block_rules)
            return RuleCache(
                version=version,
                allow_rules=allow_rules,
                block_rules=block_rules,
                ua_regex_set=ua_regex_set,
            )
        except (json.JSONDecodeError, KeyError):
            pass  # fall through to rebuild

    # Cache miss or corrupt — rebuild from DB
    return _rebuild_rule_cache(redis_client, version, cache_key)


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
            matched_rule_type=None,
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
            matched_rule_type=None,
            anomaly_score=None,
        )

    # Step 8: UA + path anomaly scoring
    recent_count = get_request_count(ip_address, "5m", redis_client)
    if recent_count > 10:
        score = score_user_agent(user_agent) + _score_path(path)
        verdict, action = _score_to_verdict(score)
        if verdict != Verdict.ALLOWED:
            return EvaluationResult(
                verdict=verdict,
                action=action,
                matched_rule_id=None,
                matched_rule_type=None,
                anomaly_score=score,
            )
        return EvaluationResult(
            verdict=Verdict.ALLOWED,
            action=None,
            matched_rule_id=None,
            matched_rule_type=None,
            anomaly_score=score,
        )

    # Step 9: Challenge escalation — auto-block IPs that ignore challenges
    challenged_count = _get_unsolved_challenge_count(ip_address, redis_client)
    if challenged_count >= conf.ICV_WAF_CHALLENGE_ESCALATION_THRESHOLD:
        record_block_verdict(ip_address, redis_client)
        return EvaluationResult(
            verdict=Verdict.BLOCKED,
            action=RuleAction.BLOCK,
            matched_rule_id=None,
            matched_rule_type=None,
            anomaly_score=None,
        )

    return EvaluationResult(
        verdict=Verdict.ALLOWED,
        action=None,
        matched_rule_id=None,
        matched_rule_type=None,
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
        # Both UA and IP/CIDR must match (BR-EVAL-007)
        # composite rules encode both patterns — expect "ua_pattern|cidr_pattern" convention
        # or store separately; fall back to checking pattern against UA first then IP
        # Per spec: composite = UA + IP/CIDR, both must match.
        # Composite rules store the UA pattern; ip_pattern comes from a second field.
        # Since the serialised rule dict only has one 'pattern', for composite we
        # check whether the pattern looks like an IP/CIDR or a UA, and require both.
        # A full implementation would store two patterns; we check ip_address first.
        ua_match = _match_ua(user_agent, pattern, match_type)
        ip_match = _match_ip(ip_address, pattern, match_type) or _match_cidr(ip_address, pattern)
        return ua_match and ip_match

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
    """Return anomaly score contribution from suspicious path patterns."""
    import re

    from icv_waf import conf

    for pattern in conf.ICV_WAF_SUSPICIOUS_PATH_PATTERNS:
        try:
            if re.search(pattern, path, re.IGNORECASE):
                return conf.ICV_WAF_SUSPICIOUS_PATH_SCORE
        except re.error:
            continue
    return 0.0


def _get_unsolved_challenge_count(ip_address: str, redis_client) -> int:
    """Count recent challenged verdicts for an IP with no solved ChallengeTokens.

    Uses Redis counter waf:challenged:{ip} incremented by the middleware
    on each CHALLENGED verdict. Returns 0 if the IP has any solved tokens
    or if Redis is unavailable.
    """
    try:
        key = f"waf:challenged:{ip_address}"
        count = redis_client.get(key)
        if not count:
            return 0
        count = int(count)

        # Check for any solved challenges — if so, reset counter
        from icv_waf.enums import ChallengeStatus
        from icv_waf.models import ChallengeToken

        if ChallengeToken.objects.filter(
            ip_address=ip_address,
            status=ChallengeStatus.SOLVED,
        ).exists():
            redis_client.delete(key)
            return 0

        return count
    except Exception:
        return 0


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

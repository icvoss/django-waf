"""
icv_waf.services — public re-exports.

All public service functions from the icv-waf package are available directly
from this module. Import individual sub-modules for full API access.
"""

from __future__ import annotations

from icv_waf.services.anomaly_detector import (
    detect_challenge_farms,
    detect_subnet_burst,
    detect_ua_rotation,
    run_all_detectors,
)
from icv_waf.services.blocklist_generator import generate_nginx_blocklist, reload_nginx
from icv_waf.services.challenge_service import (
    ChallengeExpiredError,
    ChallengeInvalidError,
    ChallengeMismatchError,
    issue_challenge,
    issue_pass_cookie,
    validate_pass_cookie,
    verify_challenge_solution,
)
from icv_waf.services.rate_limiter import check_rate_limit, get_request_count
from icv_waf.services.rule_engine import (
    EvaluationResult,
    RuleCache,
    evaluate_request,
    load_rule_cache,
    record_block_verdict,
)
from icv_waf.services.threat_feed import (
    build_telemetry_payload,
    get_or_create_install_id,
    submit_telemetry,
    sync_feed,
)
from icv_waf.services.ua_analyser import classify_ua, score_user_agent

__all__ = [
    # rule_engine
    "EvaluationResult",
    "RuleCache",
    "evaluate_request",
    "load_rule_cache",
    "record_block_verdict",
    # ua_analyser
    "score_user_agent",
    "classify_ua",
    # rate_limiter
    "check_rate_limit",
    "get_request_count",
    # blocklist_generator
    "generate_nginx_blocklist",
    "reload_nginx",
    # anomaly_detector
    "detect_ua_rotation",
    "detect_subnet_burst",
    "detect_challenge_farms",
    "run_all_detectors",
    # challenge_service
    "issue_challenge",
    "verify_challenge_solution",
    "issue_pass_cookie",
    "validate_pass_cookie",
    "ChallengeExpiredError",
    "ChallengeMismatchError",
    "ChallengeInvalidError",
    # threat_feed
    "sync_feed",
    "build_telemetry_payload",
    "submit_telemetry",
    "get_or_create_install_id",
]

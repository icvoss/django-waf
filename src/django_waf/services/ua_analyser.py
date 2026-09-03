"""
UA Analyser service for django-waf.

Provides heuristic scoring and classification of User-Agent strings. All
functions are pure, no DB or Redis access.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Pre-compiled regex patterns (module-level for performance, BR-UA-004)
# ---------------------------------------------------------------------------

# Known scraper / HTTP library strings. Used by classify_ua only (weight
# 2.5 for this pattern was removed from score_user_agent, see the comment
# on that function).
_RE_SCRAPER_LIBS = re.compile(
    r"(python-requests|Go-http-client|libwww-perl|Wget/|curl/|"
    r"urllib|[Ss]crapy|mechanize|aiohttp|httpx/)",
    re.IGNORECASE,
)

# Ancient browser versions (weight 2.0)
# MSIE 1-7, Firefox 1-3.x, Opera 1-9.x
_RE_ANCIENT_BROWSER = re.compile(
    r"(MSIE\s+[1-7]\.|Firefox/[123]\.\d|Opera/[1-9]\.\d)",
    re.IGNORECASE,
)

# Impossible OS/browser combos (weight 3.0)
# e.g. iOS token alongside Windows NT, or Android alongside iPhone
_RE_IMPOSSIBLE_COMBO_IOS_WINDOWS = re.compile(r"(iPhone|iPad|iOS).*Windows NT", re.IGNORECASE)
_RE_IMPOSSIBLE_COMBO_ANDROID_IOS = re.compile(r"Android.*iPhone|iPhone.*Android", re.IGNORECASE)
_RE_IMPOSSIBLE_COMBO_ANDROID_WINDOWS = re.compile(r"Android.*Windows NT", re.IGNORECASE)

# Missing / anomalous version format, UA has no slash-version tokens (weight 1.5)
# A legitimate browser UA almost always contains at least one "Word/X.Y" token.
_RE_VERSION_TOKEN = re.compile(r"\w+/[\d.]+")

# Known legitimate crawler identifiers (for classify_ua)
_RE_CRAWLER = re.compile(
    r"(Googlebot|Bingbot|Slurp|DuckDuckBot|Baiduspider|YandexBot|"
    r"facebookexternalhit|Twitterbot|LinkedInBot|WhatsApp|Applebot|"
    r"AhrefsBot|SemrushBot|MJ12bot|DotBot|rogerbot|SeznamBot|"
    r"PetalBot|CCBot|ia_archiver)",
    re.IGNORECASE,
)

# Known browser indicators (for classify_ua)
_RE_BROWSER = re.compile(
    r"(Mozilla/5\.0.*(Chrome|Firefox|Safari|Edge|OPR|Trident|MSIE))",
    re.IGNORECASE,
)

# Bot self-identification (for classify_ua)
_RE_BOT = re.compile(r"\bbot\b|\bspider\b|\bcrawler\b|\bscraper\b", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------


def score_user_agent(user_agent: str) -> float:
    """Compute a heuristic anomaly score for a User-Agent string.

    Applies weighted checks per BR-UA-002. Returns a value in [0.0, 10.0].
    Higher scores indicate more suspicious UAs. This is a pure function with
    no side effects.

    Args:
        user_agent: Raw User-Agent string to analyse.

    Returns:
        Float score in range [0.0, 10.0].
    """
    if not user_agent:
        return min(1.0, 10.0)  # empty UA, weight 1.0

    score: float = 0.0

    # Weight 3.0, impossible OS/browser combination
    if (
        _RE_IMPOSSIBLE_COMBO_IOS_WINDOWS.search(user_agent)
        or _RE_IMPOSSIBLE_COMBO_ANDROID_IOS.search(user_agent)
        or _RE_IMPOSSIBLE_COMBO_ANDROID_WINDOWS.search(user_agent)
    ):
        score += 3.0

    # Weight 2.0, ancient browser version
    if _RE_ANCIENT_BROWSER.search(user_agent):
        score += 2.0

    # No weight for _RE_SCRAPER_LIBS here, deliberately. It used to add
    # 2.5 for a UA honestly declaring itself an automated client (curl,
    # python-requests, Go-http-client, and so on). Measured in production
    # (issue #82): 12,053 requests penalised this way came from 22 distinct
    # IPs in a single /24, an honest UA attached to a scanner, so honesty
    # was never a signal of good behaviour there. It also inverted the
    # incentive the WAF wants: it made silence, not disclosure, the safer
    # choice. Removing the penalty does not reward honesty either, that
    # would be a score reduction, exploitable by any scanner willing to
    # send curl in its UA, it only stops punishing it. Every behavioural
    # signal (volume gating, path scoring, subnet, rate limiting,
    # fingerprint mismatch) is unchanged and still applies at full weight;
    # a short or malformed UA still scores via the checks below regardless
    # of whether it also matches a library string. Do not reintroduce this
    # weight without a fresh measurement justifying it, see issue #82.

    # Weight 1.5, missing or anomalous version format
    # Real UAs always contain at least one "Token/version" component.
    if not _RE_VERSION_TOKEN.search(user_agent):
        score += 1.5

    # Weight 1.0, extremely short (< 15 chars)
    if len(user_agent) < 15:
        score += 1.0

    return min(score, 10.0)


def classify_ua(user_agent: str) -> str:
    """Classify a UA string into a high-level category for analytics.

    Categories are: 'browser', 'crawler', 'bot', 'library', 'unknown'.

    Args:
        user_agent: Raw User-Agent string.

    Returns:
        String category.
    """
    if not user_agent:
        return "unknown"

    if _RE_CRAWLER.search(user_agent):
        return "crawler"

    if _RE_SCRAPER_LIBS.search(user_agent):
        return "library"

    if _RE_BOT.search(user_agent):
        return "bot"

    if _RE_BROWSER.search(user_agent):
        return "browser"

    return "unknown"

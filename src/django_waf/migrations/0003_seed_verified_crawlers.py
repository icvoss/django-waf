"""Seed rDNS-gated AllowRule rows for the major verified search crawlers.

Per ADR-035 and BR-CHAL-001: without these rows, Googlebot and Bingbot send
none of the browser fingerprint headers, score into the CHALLENGED band,
cannot solve the JS proof-of-work challenge, and are silently deindexed. The
seed is idempotent (keyed on rule_type + pattern via update_or_create) and
gated on DJANGO_WAF_ALLOW_VERIFIED_CRAWLERS (default True), so a site that
has opted out at migrate time does not get the rows created underneath it.
"""

from django.conf import settings
from django.db import migrations

GOOGLEBOT_PATTERN = "Googlebot"
BINGBOT_PATTERN = "bingbot"

_SEED_ROWS = [
    {
        "rule_type": "ua",
        "pattern": GOOGLEBOT_PATTERN,
        "defaults": {
            "name": "Verified Googlebot (rDNS-gated)",
            "match_type": "regex",
            "verify_rdns": True,
            "rdns_pattern": r"\.googlebot\.com$|\.google\.com$",
            "is_active": True,
            "notes": (
                "Seeded by django-waf per ADR-035 / BR-CHAL-001. Exempts verified "
                "Googlebot from WAF challenge scoring so it is never served the "
                "noindex challenge interstitial. rDNS verification (BR-EVAL-004) "
                "gates the match: a spoofed Googlebot UA from an IP whose PTR "
                "record does not end in .googlebot.com or .google.com falls "
                "through to normal scoring."
            ),
        },
    },
    {
        "rule_type": "ua",
        "pattern": BINGBOT_PATTERN,
        "defaults": {
            "name": "Verified Bingbot (rDNS-gated)",
            "match_type": "regex",
            "verify_rdns": True,
            "rdns_pattern": r"\.search\.msn\.com$",
            "is_active": True,
            "notes": (
                "Seeded by django-waf per ADR-035 / BR-CHAL-001. Exempts verified "
                "Bingbot from WAF challenge scoring so it is never served the "
                "noindex challenge interstitial. rDNS verification (BR-EVAL-004) "
                "gates the match: a spoofed Bingbot UA from an IP whose PTR record "
                "does not end in .search.msn.com falls through to normal scoring."
            ),
        },
    },
]


def seed_verified_crawlers(apps, schema_editor):
    if not getattr(settings, "DJANGO_WAF_ALLOW_VERIFIED_CRAWLERS", True):
        return

    AllowRule = apps.get_model("django_waf", "AllowRule")

    for row in _SEED_ROWS:
        AllowRule.objects.update_or_create(
            rule_type=row["rule_type"],
            pattern=row["pattern"],
            defaults=row["defaults"],
        )


def unseed_verified_crawlers(apps, schema_editor):
    AllowRule = apps.get_model("django_waf", "AllowRule")

    for row in _SEED_ROWS:
        AllowRule.objects.filter(
            rule_type=row["rule_type"],
            pattern=row["pattern"],
        ).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("django_waf", "0002_allowrule_source_and_feed_fields"),
    ]

    operations = [
        migrations.RunPython(seed_verified_crawlers, unseed_verified_crawlers),
    ]

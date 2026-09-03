"""Tests for nginx access-log ingestion source separation (#32).

Covers: source/source_event_id tagging, dedup on re-ingestion, real
log-line timestamps (not now()), rotation/truncation detection, and
source-aware anomaly detection.
"""

from __future__ import annotations

import os
import tempfile

import pytest
from django.utils import timezone

from django_waf.enums import RequestLogSource, Verdict
from django_waf.testing.factories import RequestLogFactory

# ---------------------------------------------------------------------------
# source tagging
# ---------------------------------------------------------------------------


class TestSourceTagging:
    @pytest.mark.django_db
    def test_nginx_ingestion_tags_source_nginx_log(self):
        """Rows created by parse_access_log carry source='nginx_log'."""
        log_content = '1.2.3.4 - - [07/Apr/2026:10:00:00 +0000] "GET /page/1/ HTTP/1.1" 200 1234 "-" "ua"\n'
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as fh:
            fh.write(log_content)
            log_path = fh.name

        from django_waf.models import RequestLog
        from django_waf.tasks import parse_access_log

        parse_access_log(log_path=log_path)

        record = RequestLog.objects.get(ip_address="1.2.3.4")
        assert record.source == RequestLogSource.NGINX_LOG
        assert record.source_event_id != ""

    @pytest.mark.django_db
    def test_middleware_style_row_defaults_to_middleware_source(self):
        """A row created the way WafMiddleware creates it (no source kwarg) defaults to 'middleware'.

        Regression guard for the middleware coordination point: middleware.py
        calls RequestLog.objects.create(...) without a source kwarg at both
        of its call sites, and correctness depends entirely on the model
        default doing the tagging.
        """
        from django_waf.models import RequestLog

        record = RequestLog.objects.create(
            timestamp=timezone.now(),
            ip_address="9.9.9.9",
            path="/",
            method="GET",
            verdict=Verdict.ALLOWED,
            response_code=200,
        )

        assert record.source == RequestLogSource.MIDDLEWARE
        assert record.source_event_id == ""

    @pytest.mark.django_db
    def test_middleware_and_nginx_rows_are_distinguishable(self):
        """A queryset can separate the two sources unambiguously."""
        from django_waf.models import RequestLog

        RequestLogFactory(source=RequestLogSource.MIDDLEWARE)
        RequestLogFactory(source=RequestLogSource.NGINX_LOG, source_event_id="evt-a")

        assert RequestLog.objects.filter(source=RequestLogSource.MIDDLEWARE).count() == 1
        assert RequestLog.objects.filter(source=RequestLogSource.NGINX_LOG).count() == 1


# ---------------------------------------------------------------------------
# dedup on re-ingestion
# ---------------------------------------------------------------------------


class TestReingestionDedup:
    @pytest.mark.django_db
    def test_reingesting_same_lines_does_not_create_duplicate_rows(self):
        """Re-parsing the same log lines from offset 0 does not duplicate RequestLog rows.

        Simulates the cache-eviction scenario: the offset is lost, the file
        is re-read from the start, and the partial unique constraint on
        (source, source_event_id) makes bulk_create(ignore_conflicts=True)
        silently skip the already-ingested lines.
        """
        log_content = (
            '1.2.3.4 - - [07/Apr/2026:10:00:00 +0000] "GET /a/ HTTP/1.1" 200 10 "-" "ua"\n'
            '5.6.7.8 - - [07/Apr/2026:10:00:01 +0000] "GET /b/ HTTP/1.1" 200 10 "-" "ua"\n'
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as fh:
            fh.write(log_content)
            log_path = fh.name

        from django.core.cache import cache

        from django_waf.models import RequestLog
        from django_waf.tasks import parse_access_log

        first = parse_access_log(log_path=log_path)
        assert first["created_records"] == 2
        assert RequestLog.objects.count() == 2

        # Simulate a cache eviction: offset is gone, so the whole file is
        # re-read from the start on the next run.
        offset_key = f"django_waf:access_log_offset:{log_path}"
        cache.delete(offset_key)

        second = parse_access_log(log_path=log_path)

        # The lines are parsed again (parsed_lines counts raw lines seen),
        # but bulk_create(ignore_conflicts=True) silently drops the
        # duplicates against the unique constraint, so no new rows exist.
        assert second["parsed_lines"] == 2
        assert RequestLog.objects.count() == 2


# ---------------------------------------------------------------------------
# real log-line timestamps
# ---------------------------------------------------------------------------


class TestRealTimestamps:
    @pytest.mark.django_db
    def test_stored_timestamp_equals_parsed_log_time_not_now(self):
        """RequestLog.timestamp is the parsed log-line time, not timezone.now()."""
        log_content = '1.2.3.4 - - [23/Mar/2020:10:00:00 +0000] "GET /old/ HTTP/1.1" 200 10 "-" "ua"\n'
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as fh:
            fh.write(log_content)
            log_path = fh.name

        from django_waf.models import RequestLog
        from django_waf.tasks import parse_access_log

        parse_access_log(log_path=log_path)

        record = RequestLog.objects.get(ip_address="1.2.3.4")
        # The log line is from 2020; if the code had used now() this would
        # be within the last few seconds instead.
        assert record.timestamp.year == 2020
        assert record.timestamp.month == 3
        assert record.timestamp.day == 23
        assert record.timestamp.hour == 10
        assert (timezone.now() - record.timestamp).days > 300


# ---------------------------------------------------------------------------
# rotation / truncation detection
# ---------------------------------------------------------------------------


class TestRotationDetection:
    @pytest.mark.django_db
    def test_truncated_file_resets_offset_and_reads_new_content(self):
        """A file smaller than the stored offset (rotation/truncation) resets to 0."""
        from django.core.cache import cache

        from django_waf.models import RequestLog
        from django_waf.tasks import parse_access_log

        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as fh:
            fh.write('1.2.3.4 - - [07/Apr/2026:10:00:00 +0000] "GET /long/path/here/ HTTP/1.1" 200 10 "-" "ua"\n')
            log_path = fh.name

        # Simulate a stored offset from a much larger, since-rotated file.
        offset_key = f"django_waf:access_log_offset:{log_path}"
        huge_offset = os.path.getsize(log_path) + 10_000
        cache.set(offset_key, huge_offset, timeout=None)

        # Now "rotate": truncate and write fresh, shorter content.
        with open(log_path, "w") as fh:
            fh.write('9.9.9.9 - - [07/Apr/2026:11:00:00 +0000] "GET /new/ HTTP/1.1" 200 10 "-" "ua"\n')

        result = parse_access_log(log_path=log_path)

        assert result["created_records"] == 1
        assert RequestLog.objects.filter(path="/new/").exists()

    @pytest.mark.django_db
    def test_missing_cache_offset_logs_warning_and_reads_from_start(self, caplog):
        """No cached offset (eviction or first run) is logged, not silent."""
        import logging

        from django_waf.tasks import parse_access_log

        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as fh:
            fh.write('1.2.3.4 - - [07/Apr/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 10 "-" "ua"\n')
            log_path = fh.name

        with caplog.at_level(logging.WARNING, logger="django_waf.tasks"):
            parse_access_log(log_path=log_path)

        assert any("no cached offset" in record.message.lower() for record in caplog.records)


# ---------------------------------------------------------------------------
# detector source-awareness
# ---------------------------------------------------------------------------


class TestDetectorSourceAwareness:
    @pytest.mark.django_db
    def test_detect_unsolved_challenges_excludes_nginx_log_rows(self):
        """detect_unsolved_challenges only counts source='middleware' challenged verdicts (#32).

        A status-code-inferred 'challenged' verdict from the nginx access
        log describes the same physical request the middleware already
        logged. Counting both would double the apparent challenged_count
        for an IP and could push it over min_challenged on nginx-log noise
        alone.
        """
        from django_waf.services.anomaly_detector import detect_unsolved_challenges

        ip = "203.0.113.9"
        now = timezone.now()

        # Only 2 real (middleware) challenged verdicts, below min_challenged=3.
        for _ in range(2):
            RequestLogFactory(
                ip_address=ip,
                verdict=Verdict.CHALLENGED,
                path="/products/old-page",
                referer="",
                timestamp=now,
                source=RequestLogSource.MIDDLEWARE,
            )
        # Plus nginx_log noise that would push the naive count to 5 if mixed in.
        for i in range(3):
            RequestLogFactory(
                ip_address=ip,
                verdict=Verdict.CHALLENGED,
                path="/products/old-page",
                referer="",
                timestamp=now,
                source=RequestLogSource.NGINX_LOG,
                source_event_id=f"evt-{i}",
            )

        rules = detect_unsolved_challenges(window_minutes=10, min_challenged=3)

        assert rules == []


# ---------------------------------------------------------------------------
# malformed IP does not abort the batch (#72)
# ---------------------------------------------------------------------------


class TestMalformedIPDoesNotAbortBatch:
    @pytest.mark.django_db
    def test_one_malformed_ip_is_skipped_and_good_rows_still_persist(self):
        """A malformed IP is skipped; every well-formed row in the same batch still persists.

        This is the key regression test for #72. Against the unfixed code,
        the malformed IP on the middle line reaches
        RequestLog.objects.bulk_create unvalidated. Django's own
        GenericIPAddressField validation raises ValueError from inside
        bulk_create; nothing in this task catches ValueError (only OSError
        is caught), so it propagates out of parse_access_log entirely, and
        the whole batch, including the two well-formed rows either side of
        the bad one, is lost. Fixed, the malformed line is validated and
        skipped before being appended to records_to_create, so the task
        does not raise and the two good rows are created.
        """
        log_content = (
            '1.2.3.4 - - [07/Apr/2026:10:00:00 +0000] "GET /a/ HTTP/1.1" 200 10 "-" "ua"\n'
            '999.999.999.999 - - [07/Apr/2026:10:00:01 +0000] "GET /bad/ HTTP/1.1" 200 10 "-" "ua"\n'
            '5.6.7.8 - - [07/Apr/2026:10:00:02 +0000] "GET /b/ HTTP/1.1" 200 10 "-" "ua"\n'
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as fh:
            fh.write(log_content)
            log_path = fh.name

        from django_waf.models import RequestLog
        from django_waf.tasks import parse_access_log

        # Must not raise. This is the actual defect (#72): a ValueError from
        # Django's field validation escaping the task entirely.
        result = parse_access_log(log_path=log_path)

        assert result["parsed_lines"] == 3
        assert result["created_records"] == 2
        assert result["skipped_lines"] == 1

        assert RequestLog.objects.count() == 2
        assert RequestLog.objects.filter(path="/a/").exists()
        assert RequestLog.objects.filter(path="/b/").exists()
        assert not RequestLog.objects.filter(path="/bad/").exists()

    @pytest.mark.django_db
    def test_malformed_ip_summary_logged_once_not_per_line(self, caplog):
        """Skipped malformed IPs are reported as one summarising WARNING, not one per line."""
        import logging

        log_content = (
            '999.999.999.999 - - [07/Apr/2026:10:00:00 +0000] "GET /x/ HTTP/1.1" 200 10 "-" "ua"\n'
            'also-not-an-ip - - [07/Apr/2026:10:00:01 +0000] "GET /y/ HTTP/1.1" 200 10 "-" "ua"\n'
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as fh:
            fh.write(log_content)
            log_path = fh.name

        from django_waf.tasks import parse_access_log

        with caplog.at_level(logging.WARNING, logger="django_waf.tasks"):
            result = parse_access_log(log_path=log_path)

        assert result["skipped_lines"] == 2
        malformed_ip_lines = [r for r in caplog.records if "malformed ip" in r.message.lower()]
        assert len(malformed_ip_lines) == 1
        assert "2" in malformed_ip_lines[0].message

    @pytest.mark.django_db
    def test_all_good_rows_batch_is_unaffected(self):
        """A batch of entirely well-formed rows behaves exactly as before, no regression."""
        log_content = (
            '1.2.3.4 - - [07/Apr/2026:10:00:00 +0000] "GET /a/ HTTP/1.1" 200 10 "-" "ua"\n'
            '5.6.7.8 - - [07/Apr/2026:10:00:01 +0000] "GET /b/ HTTP/1.1" 200 10 "-" "ua"\n'
            '::1 - - [07/Apr/2026:10:00:02 +0000] "GET /c/ HTTP/1.1" 200 10 "-" "ua"\n'
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as fh:
            fh.write(log_content)
            log_path = fh.name

        from django_waf.models import RequestLog
        from django_waf.tasks import parse_access_log

        result = parse_access_log(log_path=log_path)

        assert result["parsed_lines"] == 3
        assert result["created_records"] == 3
        assert result["skipped_lines"] == 0
        assert RequestLog.objects.count() == 3

    @pytest.mark.django_db
    def test_out_of_range_status_code_is_skipped_not_abort_the_batch(self):
        """A status code outside the response_code column's smallint range is skipped, not fatal.

        response_code is a PositiveSmallIntegerField (SQL smallint, max
        32767). The regex only guarantees the matched group is digits, not
        that it fits the column, so a corrupted or crafted line with an
        oversized status code is the same batch-abort failure mode as the
        malformed-IP case, and is validated the same way.
        """
        log_content = (
            '1.2.3.4 - - [07/Apr/2026:10:00:00 +0000] "GET /a/ HTTP/1.1" 999999 10 "-" "ua"\n'
            '5.6.7.8 - - [07/Apr/2026:10:00:01 +0000] "GET /b/ HTTP/1.1" 200 10 "-" "ua"\n'
        )
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as fh:
            fh.write(log_content)
            log_path = fh.name

        from django_waf.models import RequestLog
        from django_waf.tasks import parse_access_log

        result = parse_access_log(log_path=log_path)

        assert result["parsed_lines"] == 2
        assert result["created_records"] == 1
        assert result["skipped_lines"] == 1
        assert RequestLog.objects.count() == 1
        assert RequestLog.objects.filter(path="/b/").exists()
        assert not RequestLog.objects.filter(path="/a/").exists()

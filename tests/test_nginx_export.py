"""Tests for the nginx export-utility repositioning (#31).

Covers: block vs throttle variable separation, the shipped reference
package-data files, nginx -t validation with last-known-good rollback, and
that the atomic-write contract (BR-BL-002) still holds throughout.

No local nginx binary is assumed to be present in the test environment;
tests that need a specific nginx -t outcome mock subprocess.run directly,
following the pattern used by TestReloadNginx in test_services.py.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from django_waf.testing.factories import BlockRuleFactory


class TestBlockThrottleSeparation:
    def test_throttle_rule_does_not_appear_in_block_variables(self, db, tmp_path):
        """A throttle rule is written only to $waf_throttle_*, never $waf_block_*."""
        from django_waf.services.blocklist_generator import generate_nginx_blocklist

        BlockRuleFactory(
            is_active=True,
            rule_type="ip",
            match_type="exact",
            pattern="203.0.113.9",
            action="throttle",
        )
        output_file = str(tmp_path / "blocklist.conf")

        generate_nginx_blocklist(output_path=output_file)

        content = Path(output_file).read_text()
        block_section = content.split("geo $waf_block_ip")[1].split("}")[0]
        throttle_section = content.split("geo $waf_throttle_ip")[1].split("}")[0]

        assert "203.0.113.9" not in block_section
        assert "203.0.113.9" in throttle_section

    def test_block_rule_does_not_appear_in_throttle_variables(self, db, tmp_path):
        """A block rule is written only to $waf_block_*, never $waf_throttle_*."""
        from django_waf.services.blocklist_generator import generate_nginx_blocklist

        BlockRuleFactory(
            is_active=True,
            rule_type="ip",
            match_type="exact",
            pattern="198.51.100.7",
            action="block",
        )
        output_file = str(tmp_path / "blocklist.conf")

        generate_nginx_blocklist(output_path=output_file)

        content = Path(output_file).read_text()
        block_section = content.split("geo $waf_block_ip")[1].split("}")[0]
        throttle_section = content.split("geo $waf_throttle_ip")[1].split("}")[0]

        assert "198.51.100.7" in block_section
        assert "198.51.100.7" not in throttle_section

    def test_ua_throttle_rule_separated_from_ua_block_variable(self, db, tmp_path):
        """UA rules follow the same block/throttle split as IP/CIDR rules."""
        from django_waf.services.blocklist_generator import generate_nginx_blocklist

        BlockRuleFactory(
            is_active=True,
            rule_type="ua",
            match_type="exact",
            pattern="ThrottleBot/1.0",
            action="throttle",
        )
        BlockRuleFactory(
            is_active=True,
            rule_type="ua",
            match_type="exact",
            pattern="BlockBot/1.0",
            action="block",
        )
        output_file = str(tmp_path / "blocklist.conf")

        generate_nginx_blocklist(output_path=output_file)

        content = Path(output_file).read_text()
        assert "map $http_user_agent $waf_block_ua" in content
        assert "map $http_user_agent $waf_throttle_ua" in content

        block_ua_section = content.split("map $http_user_agent $waf_block_ua")[1].split("}")[0]
        throttle_ua_section = content.split("map $http_user_agent $waf_throttle_ua")[1].split("}")[0]

        assert '"BlockBot/1.0"' in block_ua_section
        assert '"BlockBot/1.0"' not in throttle_ua_section
        assert '"ThrottleBot/1.0"' in throttle_ua_section
        assert '"ThrottleBot/1.0"' not in block_ua_section

    def test_all_four_variables_declared_even_when_empty(self, db, tmp_path):
        """All four variables are always declared, even with zero matching rules."""
        from django_waf.services.blocklist_generator import generate_nginx_blocklist

        output_file = str(tmp_path / "blocklist.conf")
        generate_nginx_blocklist(output_path=output_file)

        content = Path(output_file).read_text()
        assert "geo $waf_block_ip" in content
        assert "geo $waf_throttle_ip" in content
        assert "map $http_user_agent $waf_block_ua" in content
        assert "map $http_user_agent $waf_throttle_ua" in content


class TestReferenceFilesShipped:
    def test_http_include_reference_file_exists(self):
        from django_waf.services import blocklist_generator

        conf_dir = Path(blocklist_generator.__file__).resolve().parent.parent / "conf" / "nginx"
        http_include = conf_dir / "http-include.conf.example"

        assert http_include.is_file()
        content = http_include.read_text()
        assert "http" in content.lower()
        assert "include" in content.lower()

    def test_server_include_reference_file_exists(self):
        from django_waf.services import blocklist_generator

        conf_dir = Path(blocklist_generator.__file__).resolve().parent.parent / "conf" / "nginx"
        server_include = conf_dir / "server-include.conf.example"

        assert server_include.is_file()
        content = server_include.read_text()
        assert "$waf_block_ip" in content
        assert "$waf_block_ua" in content
        assert "limit_req" in content

    def test_reference_files_document_block_and_throttle_wiring(self):
        """The server-include reference explicitly documents both action wirings."""
        from django_waf.services import blocklist_generator

        conf_dir = Path(blocklist_generator.__file__).resolve().parent.parent / "conf" / "nginx"
        content = (conf_dir / "server-include.conf.example").read_text()

        assert "return 403" in content
        assert "$waf_throttle_ip" in content
        assert "limit_req_zone" in content


class TestNginxValidationAndRollback:
    def test_validation_failure_preserves_previous_file_and_does_not_activate_candidate(self, db, tmp_path, settings):
        """On nginx -t failure, the previous good file is restored, not the broken candidate."""
        from django_waf.services.blocklist_generator import generate_nginx_blocklist

        output_file = tmp_path / "blocklist.conf"
        output_file.write_text("# previous good config\ngeo $waf_block_ip {\n    default 0;\n}\n")
        previous_content = output_file.read_text()

        settings.DJANGO_WAF_NGINX_VALIDATE = True

        BlockRuleFactory(is_active=True, rule_type="ip", match_type="exact", pattern="1.2.3.4", action="block")

        with patch("django_waf.services.blocklist_generator.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="nginx: [emerg] syntax error")
            generate_nginx_blocklist(output_path=str(output_file))

        assert output_file.read_text() == previous_content
        assert not (tmp_path / "blocklist.conf.last-good").exists()

    def test_validation_success_activates_candidate(self, db, tmp_path, settings):
        """On nginx -t success, the new candidate is activated and the rollback copy is dropped."""
        from django_waf.services.blocklist_generator import generate_nginx_blocklist

        output_file = tmp_path / "blocklist.conf"
        output_file.write_text("# previous good config\n")

        settings.DJANGO_WAF_NGINX_VALIDATE = True

        BlockRuleFactory(is_active=True, rule_type="ip", match_type="exact", pattern="5.6.7.8", action="block")

        with patch("django_waf.services.blocklist_generator.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            generate_nginx_blocklist(output_path=str(output_file))

        content = output_file.read_text()
        assert "5.6.7.8" in content
        assert not (tmp_path / "blocklist.conf.last-good").exists()

    def test_missing_first_run_validation_failure_removes_candidate_leaving_no_file(self, db, tmp_path, settings):
        """With no previous file, a failed validation removes the candidate rather than leaving it active."""
        from django_waf.services.blocklist_generator import generate_nginx_blocklist

        output_file = tmp_path / "blocklist.conf"
        settings.DJANGO_WAF_NGINX_VALIDATE = True

        with patch("django_waf.services.blocklist_generator.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="nginx: [emerg] syntax error")
            generate_nginx_blocklist(output_path=str(output_file))

        assert not output_file.exists()

    def test_missing_nginx_binary_skips_validation_and_activates_candidate(self, db, tmp_path, settings):
        """When the test command binary is absent, validation is skipped gracefully, not treated as failure."""
        from django_waf.services.blocklist_generator import generate_nginx_blocklist

        output_file = tmp_path / "blocklist.conf"
        output_file.write_text("# previous good config\n")
        settings.DJANGO_WAF_NGINX_VALIDATE = True

        BlockRuleFactory(is_active=True, rule_type="ip", match_type="exact", pattern="9.9.9.9", action="block")

        with patch(
            "django_waf.services.blocklist_generator.subprocess.run",
            side_effect=FileNotFoundError,
        ):
            generate_nginx_blocklist(output_path=str(output_file))

        content = output_file.read_text()
        assert "9.9.9.9" in content

    def test_validation_timeout_is_treated_as_failure_and_rolls_back(self, db, tmp_path, settings):
        from django_waf.services.blocklist_generator import generate_nginx_blocklist

        output_file = tmp_path / "blocklist.conf"
        output_file.write_text("# previous good config\n")
        previous_content = output_file.read_text()
        settings.DJANGO_WAF_NGINX_VALIDATE = True

        BlockRuleFactory(is_active=True, rule_type="ip", match_type="exact", pattern="8.8.8.8", action="block")

        with patch(
            "django_waf.services.blocklist_generator.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="nginx", timeout=10),
        ):
            generate_nginx_blocklist(output_path=str(output_file))

        assert output_file.read_text() == previous_content

    def test_validation_disabled_activates_unconditionally_old_behaviour(self, db, tmp_path, settings):
        """DJANGO_WAF_NGINX_VALIDATE=False reproduces the pre-#31 unconditional-activate behaviour."""
        from django_waf.services.blocklist_generator import generate_nginx_blocklist

        output_file = tmp_path / "blocklist.conf"
        output_file.write_text("# previous good config\n")
        settings.DJANGO_WAF_NGINX_VALIDATE = False

        BlockRuleFactory(is_active=True, rule_type="ip", match_type="exact", pattern="7.7.7.7", action="block")

        with patch("django_waf.services.blocklist_generator.subprocess.run") as mock_run:
            generate_nginx_blocklist(output_path=str(output_file))
            # subprocess.run must not be called at all when validation is disabled
            mock_run.assert_not_called()

        content = output_file.read_text()
        assert "7.7.7.7" in content

    def test_custom_test_command_setting_is_used(self, db, tmp_path, settings):
        """DJANGO_WAF_NGINX_TEST_COMMAND overrides the default ['nginx', '-t']."""
        from django_waf.services.blocklist_generator import generate_nginx_blocklist

        output_file = tmp_path / "blocklist.conf"
        settings.DJANGO_WAF_NGINX_VALIDATE = True
        settings.DJANGO_WAF_NGINX_TEST_COMMAND = ["/usr/local/bin/nginx-test", "-c", "custom.conf"]

        with patch("django_waf.services.blocklist_generator.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            generate_nginx_blocklist(output_path=str(output_file))

        called_command = mock_run.call_args[0][0]
        assert called_command == ["/usr/local/bin/nginx-test", "-c", "custom.conf"]


class TestAtomicWriteContractStillHolds:
    def test_write_still_uses_temp_file_then_rename(self, db, tmp_path):
        """The atomic-write contract (BR-BL-002) is unchanged by the #31 rework."""
        import os

        from django_waf.services.blocklist_generator import generate_nginx_blocklist

        output_file = str(tmp_path / "blocklist.conf")

        rename_calls = []
        real_rename = os.rename

        def tracking_rename(src, dst):
            rename_calls.append((src, dst))
            real_rename(src, dst)

        with patch("django_waf.services.blocklist_generator.os.rename", side_effect=tracking_rename):
            generate_nginx_blocklist(output_path=output_file)

        # First run, no previous file: validation is skipped (no nginx binary
        # in the test environment) or succeeds, either way exactly one
        # rename activates the candidate.
        assert len(rename_calls) == 1
        _, dst = rename_calls[0]
        assert dst == output_file

    def test_write_failure_cleans_up_temp_file(self, db, tmp_path):
        """A failure while writing the candidate cleans up the temp file, per BR-BL-002."""
        from django_waf.services.blocklist_generator import generate_nginx_blocklist

        output_file = str(tmp_path / "blocklist.conf")

        with (
            patch("django_waf.services.blocklist_generator.os.fdopen", side_effect=OSError("disk full")),
            pytest.raises(OSError, match="disk full"),
        ):
            generate_nginx_blocklist(output_path=output_file)

        # No leftover .conf.tmp files in the output directory.
        leftovers = list(Path(tmp_path).glob("*.conf.tmp"))
        assert leftovers == []

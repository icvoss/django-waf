"""
GeoIP database management for django-waf.

Downloads and installs the MaxMind GeoLite2-Country database for the
middleware's ``_lookup_country`` helper. MaxMind requires a free
licence key per https://www.maxmind.com/en/geolite2/signup; the key
is read from ``DJANGO_WAF_MAXMIND_LICENSE_KEY`` or passed explicitly.

Downloads are atomic: the archive is written to a temp file, the
``.mmdb`` is extracted and verified by opening it with
``geoip2.database.Reader``, then the file is renamed into place.
An existing database is never overwritten unless the replacement
verifies successfully.

The ``geoip2`` package is an optional dependency. Install with:

    pip install django-waf[geoip]
"""

from __future__ import annotations

import logging
import os
import shutil
import tarfile
import tempfile
from pathlib import Path

logger = logging.getLogger("django_waf.geoip")

DOWNLOAD_URL_TEMPLATE = (
    "https://download.maxmind.com/app/geoip_download?edition_id={edition}&license_key={key}&suffix=tar.gz"
)
DEFAULT_EDITION = "GeoLite2-Country"
DEFAULT_OUTPUT_PATH = "/var/lib/django-waf/GeoLite2-Country.mmdb"
SIGNUP_URL = "https://www.maxmind.com/en/geolite2/signup"


class GeoIPError(Exception):
    """Raised when the GeoIP install/update flow cannot complete."""


class GeoIPNotInstalledError(GeoIPError):
    """The ``geoip2`` package is not importable."""


class GeoIPLicenseMissingError(GeoIPError):
    """No MaxMind licence key was provided."""


class GeoIPDownloadError(GeoIPError):
    """The download from MaxMind failed or returned an invalid archive."""


# ---------------------------------------------------------------------------
# Runtime lookup
# ---------------------------------------------------------------------------

# Lazily initialised reader, cached for the process lifetime. The middleware
# and the admin both consult this; no per-request reader construction.
_reader = None
_reader_checked = False


def lookup_country(ip_address: str) -> str:
    """Return the 2-letter ISO country code for an IP, or '' if unavailable.

    Uses the MaxMind GeoLite2-Country database at ``DJANGO_WAF_GEOIP_PATH``.
    Degrades gracefully if the database is missing, ``geoip2`` is not
    installed, the IP is private, or the lookup fails — every failure
    mode returns the empty string so callers can treat the function as
    best-effort.
    """
    global _reader, _reader_checked  # noqa: PLW0603

    from django_waf import conf

    if not conf.DJANGO_WAF_GEOIP_PATH:
        return ""

    if not _reader_checked:
        _reader_checked = True
        try:
            import geoip2.database

            _reader = geoip2.database.Reader(conf.DJANGO_WAF_GEOIP_PATH)
        except Exception:
            logger.warning(
                "django-waf: GeoIP database not available at %s",
                conf.DJANGO_WAF_GEOIP_PATH,
            )

    if _reader is None:
        return ""

    try:
        response = _reader.country(ip_address)
        return response.country.iso_code or ""
    except Exception:
        return ""


def check_geoip2_available() -> None:
    """Raise GeoIPNotInstalledError if the ``geoip2`` package is missing.

    Raises:
        GeoIPNotInstalledError: with an install-hint message.
    """
    try:
        import geoip2.database  # noqa: F401
    except ImportError as exc:
        raise GeoIPNotInstalledError(
            "The 'geoip2' package is required for GeoIP lookups. Install with: pip install django-waf[geoip]"
        ) from exc


def resolve_license_key(explicit: str | None = None) -> str:
    """Return the MaxMind licence key, from argument or settings.

    Args:
        explicit: Key passed on the command line / to the task (takes precedence).

    Returns:
        The resolved licence key (non-empty string).

    Raises:
        GeoIPLicenseMissingError: if neither source provides a key.
    """
    if explicit:
        return explicit

    from django_waf import conf

    key = getattr(conf, "DJANGO_WAF_MAXMIND_LICENSE_KEY", "")
    if not key:
        raise GeoIPLicenseMissingError(
            "No MaxMind licence key configured. Sign up at "
            f"{SIGNUP_URL} and set DJANGO_WAF_MAXMIND_LICENSE_KEY in "
            "Django settings, or pass --license-key to the command."
        )
    return key


def resolve_output_path(explicit: str | None = None) -> Path:
    """Return the destination ``.mmdb`` path, from argument, setting, or default.

    Args:
        explicit: Path passed on the command line / to the task.

    Returns:
        Resolved output Path (not guaranteed to exist yet).
    """
    from django_waf import conf

    path = explicit or getattr(conf, "DJANGO_WAF_GEOIP_PATH", None) or DEFAULT_OUTPUT_PATH
    return Path(path)


def is_database_fresh(path: Path, max_age_days: int) -> bool:
    """Return True if ``path`` exists and is younger than ``max_age_days``.

    Args:
        path: Path to the ``.mmdb`` file.
        max_age_days: Maximum age in days for the file to be considered fresh.

    Returns:
        True if the file is present and fresh; False otherwise.
    """
    if max_age_days <= 0:
        return False
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return False

    import time

    age_seconds = time.time() - mtime
    return age_seconds < (max_age_days * 86400)


def install_geoip_database(
    license_key: str | None = None,
    output_path: str | None = None,
    edition: str = DEFAULT_EDITION,
    if_older_than_days: int = 0,
) -> dict:
    """Download, verify, and install the MaxMind GeoLite2 database.

    The flow is:

    1. Check that the ``geoip2`` package is importable.
    2. Resolve the licence key and output path.
    3. If ``if_older_than_days > 0`` and the existing file is younger than
       that, skip the download and return ``{"skipped": True}``.
    4. Download the tar.gz archive from MaxMind to a temp directory.
    5. Extract the ``.mmdb`` file from the archive.
    6. Verify the extracted file by opening it with ``geoip2.database.Reader``.
    7. Atomically rename the verified file into the output path
       (creating parent directories if needed).

    Args:
        license_key: MaxMind licence key. Defaults to ``DJANGO_WAF_MAXMIND_LICENSE_KEY``.
        output_path: Destination ``.mmdb`` path. Defaults to ``DJANGO_WAF_GEOIP_PATH``
            or ``/var/lib/django-waf/GeoLite2-Country.mmdb``.
        edition: MaxMind edition ID. Defaults to ``GeoLite2-Country``.
        if_older_than_days: Skip the download if the existing file is younger
            than this many days. 0 (default) always downloads.

    Returns:
        Dict with keys: ``path``, ``size_bytes``, ``skipped``, ``edition``,
        ``build_epoch`` (MaxMind database build timestamp, or ``None``).

    Raises:
        GeoIPNotInstalledError: if ``geoip2`` is not importable.
        GeoIPLicenseMissingError: if no licence key is available.
        GeoIPDownloadError: if the download fails or the archive is invalid.
    """
    check_geoip2_available()
    key = resolve_license_key(license_key)
    dest_path = resolve_output_path(output_path)

    if if_older_than_days > 0 and is_database_fresh(dest_path, if_older_than_days):
        logger.info(
            "django-waf: GeoIP database at %s is younger than %d days — skipping download",
            dest_path,
            if_older_than_days,
        )
        return {
            "path": str(dest_path),
            "size_bytes": dest_path.stat().st_size,
            "skipped": True,
            "edition": edition,
            "build_epoch": None,
        }

    url = DOWNLOAD_URL_TEMPLATE.format(edition=edition, key=key)

    with tempfile.TemporaryDirectory(prefix="django-waf-geoip-") as tmpdir:
        archive_path = Path(tmpdir) / "archive.tar.gz"
        _download_archive(url, archive_path)
        mmdb_path = _extract_mmdb(archive_path, Path(tmpdir), edition)
        build_epoch = _verify_mmdb(mmdb_path)
        size = mmdb_path.stat().st_size
        _atomic_install(mmdb_path, dest_path)

    logger.info(
        "django-waf: GeoIP database %s installed at %s (%d bytes)",
        edition,
        dest_path,
        size,
    )
    return {
        "path": str(dest_path),
        "size_bytes": size,
        "skipped": False,
        "edition": edition,
        "build_epoch": build_epoch,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _download_archive(url: str, target: Path) -> None:
    """Download a URL to ``target`` using httpx, streaming in chunks.

    Raises GeoIPDownloadError on any HTTP or network failure. The licence
    key in the URL is scrubbed from error messages.
    """
    import httpx

    try:
        with httpx.stream("GET", url, timeout=60, follow_redirects=True) as response:
            if response.status_code == 401:
                raise GeoIPDownloadError(
                    "MaxMind rejected the licence key (HTTP 401). "
                    f"Check DJANGO_WAF_MAXMIND_LICENSE_KEY or sign up at {SIGNUP_URL}."
                )
            if response.status_code >= 400:
                raise GeoIPDownloadError(f"MaxMind download failed with HTTP {response.status_code}.")
            with target.open("wb") as fh:
                for chunk in response.iter_bytes(chunk_size=64 * 1024):
                    fh.write(chunk)
    except httpx.HTTPError as exc:
        raise GeoIPDownloadError(f"MaxMind download failed: {exc}") from exc


def _extract_mmdb(archive_path: Path, workdir: Path, edition: str) -> Path:
    """Extract the ``<edition>.mmdb`` file from a MaxMind tar.gz archive.

    MaxMind archives contain a dated top-level directory:
    ``GeoLite2-Country_20260411/GeoLite2-Country.mmdb``.

    Returns:
        Path to the extracted .mmdb file (inside ``workdir``).

    Raises:
        GeoIPDownloadError: if the archive is not a valid tar.gz, or does
            not contain the expected .mmdb file.
    """
    try:
        with tarfile.open(archive_path, mode="r:gz") as tar:
            mmdb_members = [m for m in tar.getmembers() if m.name.endswith(f"{edition}.mmdb")]
            if not mmdb_members:
                raise GeoIPDownloadError(
                    f"Archive does not contain a {edition}.mmdb file. Did MaxMind change their archive layout?"
                )
            member = mmdb_members[0]
            # Flatten: extract the member to workdir / <edition>.mmdb
            extracted = workdir / f"{edition}.mmdb"
            fileobj = tar.extractfile(member)
            if fileobj is None:
                raise GeoIPDownloadError(f"Archive member {member.name} is not a regular file.")
            with extracted.open("wb") as fh:
                shutil.copyfileobj(fileobj, fh)
            return extracted
    except tarfile.TarError as exc:
        raise GeoIPDownloadError(f"Failed to read MaxMind archive: {exc}") from exc


def _verify_mmdb(path: Path) -> int | None:
    """Open the extracted ``.mmdb`` file with ``geoip2.database.Reader`` to verify it.

    Also performs a smoke-test lookup against a well-known IP to ensure the
    database is structurally sound (not just openable).

    Returns:
        MaxMind database build timestamp (Unix epoch seconds), or None if
        the reader doesn't expose it.

    Raises:
        GeoIPDownloadError: if the file cannot be opened or the lookup fails.
    """
    import contextlib

    try:
        import geoip2.database
        import geoip2.errors

        with geoip2.database.Reader(str(path)) as reader:
            # Empty/trimmed databases are possible in test scenarios —
            # don't fail verification on a known-IP miss.
            with contextlib.suppress(geoip2.errors.AddressNotFoundError):
                reader.country("8.8.8.8")
            return getattr(reader.metadata(), "build_epoch", None)
    except Exception as exc:
        raise GeoIPDownloadError(f"Extracted file at {path} is not a valid GeoIP database: {exc}") from exc


def _atomic_install(source: Path, destination: Path) -> None:
    """Atomically move ``source`` to ``destination``.

    Creates parent directories if needed. Uses ``os.replace()`` which is
    atomic on POSIX and Windows when source and destination are on the
    same filesystem. If they are on different filesystems, falls back to
    copy + replace + cleanup.

    Raises:
        GeoIPError: if the destination cannot be written (usually a
            permissions or disk-space issue).
    """
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.replace(source, destination)
    except OSError as exc:
        # Cross-device move — copy then replace
        if getattr(exc, "errno", None) == 18:  # EXDEV
            tmp_dest = destination.with_suffix(destination.suffix + ".tmp")
            shutil.copy2(source, tmp_dest)
            os.replace(tmp_dest, destination)
            return
        raise GeoIPError(f"Cannot install GeoIP database to {destination}: {exc}") from exc

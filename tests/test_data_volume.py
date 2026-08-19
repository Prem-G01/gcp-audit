from __future__ import annotations

import pytest

from src.enrichment import data_volume
from src.models import EnrichedEvent


def _gcs_event(**overrides) -> EnrichedEvent:
    defaults = dict(
        method_name="storage.objects.get",
        resource_name="projects/_/buckets/some-bucket/objects/report.csv",
        raw_log_id="log-1",
        raw={},
    )
    defaults.update(overrides)
    return EnrichedEvent(**defaults)


def _bq_extract_event(**overrides) -> EnrichedEvent:
    defaults = dict(
        method_name="google.cloud.bigquery.v2.JobService.InsertJob",
        resource_name="projects/p/jobs/test-extract-job-001",
        raw_log_id="log-2",
        raw={"protoPayload": {"metadata": {"jobChange": {"job": {"jobConfig": {"type": "EXTRACT"}}}}}},
    )
    defaults.update(overrides)
    return EnrichedEvent(**defaults)


@pytest.mark.parametrize(
    ("n", "expected"),
    [
        (0, "0 B"),
        (512, "512 B"),
        (1024, "1.0 KB"),
        (1536, "1.5 KB"),
        (1024**2, "1.0 MB"),
        (int(1024**2 * 128.4), "128.4 MB"),
        (1024**3, "1.0 GB"),
        (int(1024**3 * 2.5), "2.5 GB"),
    ],
)
def test_format_bytes(n: int, expected: str) -> None:
    assert data_volume._format_bytes(n) == expected


def test_non_matching_event_returns_unchanged_without_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    called = []
    monkeypatch.setattr(data_volume, "_lookup_gcs_object_size", lambda *a: called.append(1))
    monkeypatch.setattr(data_volume, "_lookup_bq_job_bytes", lambda *a: called.append(1))

    event = EnrichedEvent(method_name="SetIamPolicy", resource_name="projects/p", raw={})
    result = data_volume.enrich_data_volume(event)

    assert result is event
    assert called == []


def test_gcs_download_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(data_volume, "_lookup_gcs_object_size", lambda bucket, obj: 134_744_678)

    result = data_volume.enrich_data_volume(_gcs_event())

    assert result.data_size_bytes == 134_744_678
    assert result.data_size_display == "128.5 MB"


def test_gcs_download_lookup_failure_degrades_without_raising(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_error(bucket, obj):
        raise RuntimeError("permission denied")

    monkeypatch.setattr(data_volume, "_lookup_gcs_object_size", raise_error)

    result = data_volume.enrich_data_volume(_gcs_event())

    assert result.data_size_bytes is None
    assert result.data_size_display is None


def test_gcs_download_unparseable_resource_name_skips_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    called = []
    monkeypatch.setattr(data_volume, "_lookup_gcs_object_size", lambda *a: called.append(1))

    result = data_volume.enrich_data_volume(_gcs_event(resource_name="not-a-gcs-resource-name"))

    assert called == []
    assert result.data_size_bytes is None


def test_bq_extract_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(data_volume, "_lookup_bq_job_bytes", lambda project_id, job_id: 2_684_354_560)

    result = data_volume.enrich_data_volume(_bq_extract_event())

    assert result.data_size_bytes == 2_684_354_560
    assert result.data_size_display == "2.5 GB"


def test_bq_extract_lookup_failure_degrades_without_raising(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_error(project_id, job_id):
        raise RuntimeError("job not found")

    monkeypatch.setattr(data_volume, "_lookup_bq_job_bytes", raise_error)

    result = data_volume.enrich_data_volume(_bq_extract_event())

    assert result.data_size_bytes is None
    assert result.data_size_display is None


def test_bq_insert_job_without_extract_metadata_is_not_matched(monkeypatch: pytest.MonkeyPatch) -> None:
    called = []
    monkeypatch.setattr(data_volume, "_lookup_bq_job_bytes", lambda *a: called.append(1))

    raw = {"protoPayload": {"metadata": {"jobChange": {"job": {"jobConfig": {"type": "QUERY"}}}}}}
    event = _bq_extract_event(raw=raw)
    result = data_volume.enrich_data_volume(event)

    assert called == []
    assert result.data_size_bytes is None

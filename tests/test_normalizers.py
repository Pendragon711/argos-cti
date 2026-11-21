from argos.models import ArtifactType
from argos.normalizers import normalize_indicator


def test_normalize_defanged_and_standard_iocs() -> None:
    ip_res = normalize_indicator("192[.]0[.]2[.]45")
    assert ip_res.artifact_type == ArtifactType.IPV4
    assert ip_res.value == "192.0.2.45"
    assert ip_res.original_value == "192[.]0[.]2[.]45"

    dom_res = normalize_indicator("Example[.]COM.")
    assert dom_res.artifact_type == ArtifactType.DOMAIN
    assert dom_res.value == "example.com"
    assert dom_res.original_value == "Example[.]COM."

    url_res = normalize_indicator("hxxps://evil[.]example/payload")
    assert url_res.artifact_type == ArtifactType.URL
    assert url_res.value == "https://evil.example/payload"

    sha256_res = normalize_indicator("A" * 64)
    assert sha256_res.artifact_type == ArtifactType.HASH_SHA256
    assert sha256_res.value == "a" * 64

    asn_res = normalize_indicator("as13335")
    assert asn_res.artifact_type == ArtifactType.ASN
    assert asn_res.value == "AS13335"

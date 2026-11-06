import base64

import pytest

from scanner.checks.dkim import (
    COMMON_SELECTORS,
    DkimCheck,
    evaluate_dkim,
    parse_dkim,
    rsa_modulus_bits,
)
from scanner.types import CheckContext

# Real public keys generated with: openssl genrsa N | openssl rsa -pubout -outform DER | base64
REAL_1024 = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDTckqN9rz7+mM1wSRIJE8kJiol"
    "+fOAT5LMOhFp2HQsI+Ny7L7A6Wgz5s688Y4U2aGqgpTWnsAOaBqkkmzhM93Ji3zz"
    "uAzbIZAvaNkEGu4bA5zUPty+c7ft8VvM84+P5N8/8IdbWPZJdZC9aZB3RnB1Miwx"
    "MTfH0jeBv0IFMuqamwIDAQAB"
)
REAL_2048 = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtkE3Bmz34t8d2YukKmtd"
    "pT/JiOK1ANCh2gUCxuUIwRbVsLwvwpvjVf+c2gfBHTrFdy1IaQKO91dx1qZ/gPPn"
    "m6br0LmUkt+KRJj2BVNvWuh5fMpyxv81VrAFtbDDmceurPk4gyXBMqmotTtma+PJ"
    "6yu+TRU3E58xUXMSdIxt6fnfOLv9PZkJ/NLcTRm8WaCNokVYDAoxZoiVIv55DVcp"
    "r3JirdA3APWugu9H7CsIAEDGQktRhPr9Z2pXogoYP4loHxLfe8Iv9LqZfcIYaTmr"
    "Foi9yGvOJ5p06puTwX8w26+l68TxeHbBcjw+Mtp8aEutEmqysZFsEUY8KjzA0YMn"
    "2QIDAQAB"
)
REAL_2048_PKCS1 = (
    "MIIBCgKCAQEAtkE3Bmz34t8d2YukKmtdpT/JiOK1ANCh2gUCxuUIwRbVsLwvwpvj"
    "Vf+c2gfBHTrFdy1IaQKO91dx1qZ/gPPnm6br0LmUkt+KRJj2BVNvWuh5fMpyxv81"
    "VrAFtbDDmceurPk4gyXBMqmotTtma+PJ6yu+TRU3E58xUXMSdIxt6fnfOLv9PZkJ"
    "/NLcTRm8WaCNokVYDAoxZoiVIv55DVcpr3JirdA3APWugu9H7CsIAEDGQktRhPr9"
    "Z2pXogoYP4loHxLfe8Iv9LqZfcIYaTmrFoi9yGvOJ5p06puTwX8w26+l68TxeHbB"
    "cjw+Mtp8aEutEmqysZFsEUY8KjzA0YMn2QIDAQAB"
)  # the older "RSAPublicKey" encoding some providers publish


def _der(tag: int, content: bytes) -> bytes:
    n = len(content)
    length = bytes([n]) if n < 0x80 else (b"\x82" + n.to_bytes(2, "big"))
    return bytes([tag]) + length + content


def fake_rsa_key(bits: int) -> str:
    """A structurally valid SubjectPublicKeyInfo whose modulus has exactly `bits` bits."""
    modulus = ((1 << (bits - 1)) | 1).to_bytes((bits + 7) // 8, "big")
    integer = lambda b: _der(0x02, (b"\x00" + b) if b[0] & 0x80 else b)  # noqa: E731
    rsa = _der(0x30, integer(modulus) + integer(b"\x01\x00\x01"))
    algorithm = _der(0x30, _der(0x06, bytes.fromhex("2a864886f70d010101")) + _der(0x05, b""))
    return base64.b64encode(_der(0x30, algorithm + _der(0x03, b"\x00" + rsa))).decode()


def record(key, **tags):
    extra = "".join(f"; {k}={v}" for k, v in tags.items())
    return f"v=DKIM1; k=rsa; p={key}{extra}"


def keys(results):
    return [r.check_key for r in results]


# ---- reading key sizes -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("key", "bits"), [(REAL_1024, 1024), (REAL_2048, 2048), (REAL_2048_PKCS1, 2048)]
)
def test_real_openssl_keys_are_read_correctly(key, bits):
    assert rsa_modulus_bits(key) == bits


@pytest.mark.parametrize("bits", [512, 768, 1024, 1536, 2048, 3072, 4096])
def test_generated_keys_of_any_size(bits):
    assert rsa_modulus_bits(fake_rsa_key(bits)) == bits


@pytest.mark.parametrize(
    "garbage",
    ["", "not base64!!", "AAAA", base64.b64encode(b"\x30\x05\x01").decode(),
     base64.b64encode(b"\x31\x00").decode(), base64.b64encode(b"\x30\x82\xff\xff\x02").decode()],
)  # fmt: skip
def test_unreadable_keys_return_none_instead_of_raising(garbage):
    assert rsa_modulus_bits(garbage) is None


def test_whitespace_wrapped_keys_are_accepted():
    wrapped = " ".join(REAL_2048[i : i + 64] for i in range(0, len(REAL_2048), 64))
    assert rsa_modulus_bits(wrapped) == 2048


def test_parse_joins_wrapped_key_lines_and_lowercases_tag_names():
    tags = parse_dkim("v=DKIM1; K=rsa; p=AAAA BBBB\n CCCC")
    assert tags == {"v": "DKIM1", "k": "rsa", "p": "AAAABBBBCCCC"}


# ---- the rules ---------------------------------------------------------------------------------


def test_nothing_found_is_reported_gently():
    results = evaluate_dkim("acme.example", {})
    assert keys(results) == ["EMAIL_DKIM_NOT_FOUND"]
    assert results[0].severity == "low"
    assert results[0].evidence == {"selectors_checked": len(COMMON_SELECTORS)}


def test_a_strong_key_has_no_findings():
    assert evaluate_dkim("acme.example", {"google": [record(REAL_2048)]}) == []


def test_a_1024_bit_key_is_medium():
    results = evaluate_dkim("acme.example", {"default": [record(REAL_1024)]})
    assert keys(results) == ["EMAIL_DKIM_WEAK_KEY"]
    assert results[0].severity == "medium"
    assert results[0].asset == "default._domainkey.acme.example"
    assert results[0].evidence == {"selector": "default", "bits": 1024}


def test_a_512_bit_key_is_high():
    results = evaluate_dkim("acme.example", {"s1": [record(fake_rsa_key(512))]})
    assert results[0].severity == "high"


def test_each_weak_selector_gets_its_own_finding():
    found = {"s1": [record(REAL_1024)], "s2": [record(REAL_1024)], "google": [record(REAL_2048)]}
    assets = [r.asset for r in evaluate_dkim("acme.example", found)]
    assert assets == ["s1._domainkey.acme.example", "s2._domainkey.acme.example"]


def test_a_revoked_key_counts_as_not_found():
    assert keys(evaluate_dkim("acme.example", {"old": ["v=DKIM1; p="]})) == ["EMAIL_DKIM_NOT_FOUND"]


def test_a_revoked_key_does_not_hide_a_strong_one():
    found = {"old": ["v=DKIM1; p="], "new": [record(REAL_2048)]}
    assert evaluate_dkim("acme.example", found) == []


def test_non_rsa_keys_are_not_judged():
    assert (
        evaluate_dkim(
            "acme.example",
            {"ed": ["v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="]},
        )
        == []
    )


def test_unreadable_keys_are_skipped_not_guessed_about():
    assert evaluate_dkim("acme.example", {"x": ["v=DKIM1; p=%%%notbase64"]}) == []


def test_a_record_for_another_protocol_is_ignored():
    assert keys(evaluate_dkim("acme.example", {"x": ["v=SPF1 -all"]})) == ["EMAIL_DKIM_NOT_FOUND"]


# ---- the check ---------------------------------------------------------------------------------


class Dns:
    def __init__(self, zone):
        self.zone, self.queries = zone, []

    def txt(self, name):
        self.queries.append(name)
        return self.zone.get(name, [])


def test_the_check_probes_every_common_selector():
    dns = Dns({"google._domainkey.acme.example": [record(REAL_1024)]})
    results = DkimCheck().run(CheckContext("acme.example", dns))
    assert keys(results) == ["EMAIL_DKIM_WEAK_KEY"]
    assert dns.queries == [f"{s}._domainkey.acme.example" for s in COMMON_SELECTORS]


def test_a_dns_failure_on_any_selector_fails_the_check():
    class Flaky:
        def txt(self, name):
            if name.startswith("s1."):
                raise TimeoutError("dns down")
            return []

    with pytest.raises(TimeoutError):
        DkimCheck().run(CheckContext("acme.example", Flaky()))
"""DKIM: a cryptographic signature on outgoing mail, verified with a public key published in DNS.

The selector (the name the key is published under) is chosen by the sender and cannot be listed
from outside, so this check probes the selectors that common providers use. Not finding a key is
therefore reported gently ("we could not find"), never as "you have no DKIM".

`evaluate_dkim` is a pure function of the records found. `rsa_modulus_bits` reads an RSA key's size
from its DER encoding with a small strict parser, so no cryptography dependency is needed.
"""

import base64
from typing import NamedTuple

from scanner.registry import register
from scanner.types import CheckContext, CheckResult, Severity

COMMON_SELECTORS = (
    "default", "google", "selector1", "selector2", "k1", "k2", "k3",
    "s1", "s2", "dkim", "mail", "smtp", "mandrill", "zoho",
)  # fmt: skip

MIN_RECOMMENDED_BITS = 2048
_SEQUENCE, _INTEGER, _BIT_STRING = 0x30, 0x02, 0x03


class _Tlv(NamedTuple):
    tag: int
    start: int  # first content byte
    end: int  # one past the last content byte


def _read_tlv(data: bytes, pos: int) -> _Tlv | None:
    """Read one DER tag-length-value at `pos`; None if it is malformed or runs past the data."""
    if pos + 2 > len(data):
        return None
    tag, length, pos = data[pos], data[pos + 1], pos + 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or pos + count > len(data):
            return None
        length, pos = int.from_bytes(data[pos : pos + count], "big"), pos + count
    end = pos + length
    return _Tlv(tag, pos, end) if end <= len(data) else None


def rsa_modulus_bits(public_key_b64: str) -> int | None:
    """Size in bits of an RSA public key (SubjectPublicKeyInfo or PKCS#1), or None if unreadable."""
    try:
        der = base64.b64decode("".join(public_key_b64.split()), validate=True)
    except ValueError:
        return None
    outer = _read_tlv(der, 0)
    if outer is None or outer.tag != _SEQUENCE:
        return None
    first = _read_tlv(der, outer.start)
    if first is None:
        return None

    modulus: _Tlv | None
    if first.tag == _INTEGER:  # PKCS#1 RSAPublicKey: SEQUENCE { modulus, exponent }
        modulus = first
    elif first.tag == _SEQUENCE:  # SubjectPublicKeyInfo: SEQUENCE { algorithm, BIT STRING }
        bit_string = _read_tlv(der, first.end)
        if bit_string is None or bit_string.tag != _BIT_STRING:
            return None
        rsa_key = _read_tlv(der, bit_string.start + 1)  # skip the "unused bits" byte
        if rsa_key is None or rsa_key.tag != _SEQUENCE:
            return None
        modulus = _read_tlv(der, rsa_key.start)
        if modulus is None or modulus.tag != _INTEGER:
            return None
    else:
        return None

    value = int.from_bytes(der[modulus.start : modulus.end], "big")
    return value.bit_length() or None


def parse_dkim(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        if "=" in part:
            name, _, value = part.partition("=")
            tags[name.strip().lower()] = "".join(value.split())  # keys are often wrapped on lines
    return tags


def evaluate_dkim(domain: str, found: dict[str, list[str]]) -> list[CheckResult]:
    """`found` maps selector -> the TXT records published at `<selector>._domainkey.<domain>`."""
    keys: dict[str, tuple[str, str]] = {}
    for selector, records in found.items():
        for record in records:
            tags = parse_dkim(record)
            if tags.get("v", "DKIM1").upper() != "DKIM1":
                continue
            public_key = tags.get("p", "")
            if public_key:  # an empty p= means the key was revoked on purpose
                keys[selector] = (tags.get("k", "rsa").lower(), public_key)

    if not keys:
        not_found: dict[str, object] = {"selectors_checked": len(COMMON_SELECTORS)}
        return [CheckResult("EMAIL_DKIM_NOT_FOUND", Severity.LOW, 0.3, domain, not_found)]

    results: list[CheckResult] = []
    for selector, (kind, public_key) in sorted(keys.items()):
        if kind != "rsa":
            continue
        bits = rsa_modulus_bits(public_key)
        if bits is None or bits >= MIN_RECOMMENDED_BITS:
            continue  # unreadable keys are skipped rather than guessed about
        severity, exploitability = (Severity.HIGH, 0.6) if bits < 1024 else (Severity.MEDIUM, 0.3)
        asset = f"{selector}._domainkey.{domain}"
        weak: dict[str, object] = {"selector": selector, "bits": bits}
        results.append(CheckResult("EMAIL_DKIM_WEAK_KEY", severity, exploitability, asset, weak))
    return results


class DkimCheck:
    key = "EMAIL_DKIM"
    requires_verification = False
    emits: tuple[str, ...] = ("EMAIL_DKIM_NOT_FOUND", "EMAIL_DKIM_WEAK_KEY")

    def run(self, ctx: CheckContext) -> list[CheckResult]:
        found: dict[str, list[str]] = {}
        for selector in COMMON_SELECTORS:
            records = ctx.resolver.txt(f"{selector}._domainkey.{ctx.domain}")
            if records:
                found[selector] = records
        return evaluate_dkim(ctx.domain, found)


register(DkimCheck())
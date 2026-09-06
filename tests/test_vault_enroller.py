import base64
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ed25519, x448
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import NameOID

from pico_vault_enroller import crypto, device
from pico_vault_enroller.cli import main
from pico_vault_enroller.device import APP_OPENPGP, APP_PIV, _read_last_error, _vault_apdu, _verify_card_pin


def test_vault_id_is_deterministic_and_256_bit():
    key = bytes(range(32))

    assert crypto._vault_id(key) == crypto._vault_id(key)
    assert len(crypto._vault_id(key)) == 32
    assert crypto._vault_id(key) != crypto._vault_id(bytes(range(1, 33)))


def test_enrollment_round_trip_and_wrong_passphrase(tmp_path):
    path = tmp_path / "enrollment.json"
    private = x448.X448PrivateKey.generate()
    vault_key = bytes(range(32))

    crypto._save(path, "correct horse", vault_key, private, b"certificate", "office")

    value, stored = crypto._read_enrollment_json(path, "correct horse")
    assert value["vault_id"] == crypto._vault_id(vault_key).hex()
    assert "license_id" not in stored
    assert stored["label"] == "office"
    assert base64.b64decode(stored["kvault"]) == vault_key

    with pytest.raises(InvalidTag):
        crypto._read_enrollment_json(path, "wrong horse")


def test_hpke_enrollment_round_trip_and_tampering():
    sender = x448.X448PrivateKey.generate()
    recipient = x448.X448PrivateKey.generate()
    certificate = b"certificate"
    recipient_public = recipient.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    sender_public = sender.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    challenge = bytes(range(32))
    encrypted = crypto._hpke_auth_encrypt(certificate, sender, recipient_public, challenge, b"vault payload")

    assert crypto._hpke_auth_decrypt(certificate, recipient, sender_public, challenge, encrypted) == b"vault payload"

    tampered = bytearray(encrypted)
    tampered[-1] ^= 1
    with pytest.raises(InvalidTag):
        crypto._hpke_auth_decrypt(certificate, recipient, sender_public, challenge, bytes(tampered))


def test_legacy_enrollment_round_trip():
    sender = x448.X448PrivateKey.generate()
    recipient = x448.X448PrivateKey.generate()
    signing_key = ed25519.Ed25519PrivateKey.generate()
    now = datetime.now(timezone.utc)
    certificate = x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])).issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])).public_key(sender.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + timedelta(days=365)).sign(signing_key, algorithm=None).public_bytes(Encoding.DER)
    recipient_public = recipient.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    sender_public = sender.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    challenge = bytes(range(32))
    encrypted = crypto._legacy_enrollment_encrypt(certificate, sender, recipient_public, challenge, b"vault payload")
    info = crypto._ENROLL_INFO + challenge + sender_public + recipient_public
    shared = recipient.exchange(x448.X448PublicKey.from_public_bytes(sender_public))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared)

    assert AESGCM(key).decrypt(encrypted[:12], encrypted[12:], info) == b"vault payload"


@pytest.mark.parametrize(
    ("status", "expected"),
    [({2: True}, crypto._VAULT_ENROLLMENT_PROTOCOL_LEGACY), ({2: True, 6: 1}, crypto._VAULT_ENROLLMENT_PROTOCOL_LEGACY), ({2: True, 6: 2}, crypto._VAULT_ENROLLMENT_PROTOCOL)],
)
def test_status_selects_enrollment_protocol(monkeypatch, status, expected):
    monkeypatch.setattr(device, "_vendor", lambda *args, **kwargs: status)

    assert device._wait_for_enrollment_mode(object(), report=lambda _: None) == expected


def test_label_slug_is_bounded_and_filesystem_safe():
    slug = crypto._label_slug("  office / backup: 2026  ")

    assert slug == "office_backup_2026"
    assert len(crypto._label_slug("x" * 100)) == 40


def test_version_and_help_commands(capsys):
    assert main(["version"]) == 0
    assert capsys.readouterr().out.strip() == "2.0.1"

    assert main(["help"]) == 0
    assert "create" in capsys.readouterr().out


def test_card_pin_uses_app_specific_verify_reference():
    calls = []

    class Card:
        def send(self, ins, p1=0, p2=0, data=b""):
            calls.append((ins, p1, p2, data))

    card = Card()
    _verify_card_pin(card, APP_OPENPGP, "pw3")
    _verify_card_pin(card, APP_PIV, "12345678")
    _vault_apdu(card, 3, b"packet")

    assert calls == [(0x20, 0, 0x83, b"pw3"), (0x20, 0, 0x80, b"12345678"), (0xf2, 3, 0, b"packet")]


def test_last_error_reads_rescue_interface(monkeypatch):
    calls = []

    class Rescue:
        @classmethod
        def list_devices(cls, aid):
            assert aid == bytes.fromhex("a0583fc19b7e4f21")
            yield cls()

        def send_with_cla(self, cla, ins, p1=0, p2=0, data=b""):
            calls.append((cla, ins, p1, p2, data))
            return b"vault import: decryption failed"

    monkeypatch.setattr("pico_vault_enroller.device._PcscApduDevice", Rescue)

    assert _read_last_error() == "vault import: decryption failed"
    assert calls == [(0x80, 0x1E, 0x05, 0, b"")]


def test_piv_pin_is_fixed_width_and_ff_padded():
    calls = []

    class Card:
        def send(self, ins, p1=0, p2=0, data=b""):
            calls.append((ins, p1, p2, data))

    _verify_card_pin(Card(), APP_PIV, "123456")

    assert calls == [(0x20, 0, 0x80, b"123456\xff\xff")]
    with pytest.raises(ValueError, match="6 to 8"):
        _verify_card_pin(Card(), APP_PIV, "0123456789")


def test_enroll_command_accepts_each_application():
    from pico_vault_enroller.cli import _build_parser

    parser, _ = _build_parser()
    for app in ("fido", "openpgp", "piv"):
        args = parser.parse_args(["enroll", "--license-file", "license", "--app", app])
        assert args.app == app


def test_create_command_accepts_gui_equivalent_flags(tmp_path, capsys):
    license_file = tmp_path / "license.bin"
    envelope = tmp_path / "enrollment.json"
    license_file.write_bytes(b"opaque license bytes")

    assert main(["create", "--license-file", str(license_file), "--passphrase", "secret", "--confirm-passphrase", "secret", "--label", "test", "--envelope", str(envelope)]) == 0
    assert envelope.is_file()
    assert "Created enrollment envelope" in capsys.readouterr().out


def test_certificate_request_sends_license_as_opaque_bytes(tmp_path, monkeypatch):
    license_file = tmp_path / "license.bin"
    license_file.write_bytes(b"opaque license bytes\x00\xff")
    signing_key = ed25519.Ed25519PrivateKey.generate()
    now = datetime.now(timezone.utc)
    certificate = x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])).issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])).public_key(signing_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + timedelta(days=365)).sign(signing_key, algorithm=None).public_bytes(Encoding.PEM)
    captured = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps({"certificate": certificate.decode(), "reused": False}).encode()

    def urlopen(request, timeout):
        captured["request"] = request
        return Response()

    monkeypatch.setattr(crypto.urllib.request, "urlopen", urlopen)
    crypto._request_certificate("https://backend.example/", license_file, b"test csr")

    body = json.loads(captured["request"].data)
    assert base64.b64decode(body["license"]) == b"opaque license bytes\x00\xff"
    assert body["csr"] == "test csr"
    assert "license_id" not in body
    assert captured["request"].get_header("Content-type") == "application/json"


def test_enroll_reuses_certificate_from_envelope(tmp_path, monkeypatch):
    from pico_vault_enroller import device

    envelope = tmp_path / "enrollment.json"
    license_file = tmp_path / "license.bin"
    license_file.write_bytes(b"license")
    private = x448.X448PrivateKey.generate()
    vault_key = bytes(range(32))
    signing_key = ed25519.Ed25519PrivateKey.generate()
    now = datetime.now(timezone.utc)
    certificate = x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])).issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")])).public_key(private.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + timedelta(days=365)).sign(signing_key, algorithm=None).public_bytes(Encoding.DER)
    crypto._save(envelope, "secret", vault_key, private, certificate, "test")

    def request_certificate(*args):
        raise AssertionError("backend certificate request was not expected")

    monkeypatch.setattr(device, "_request_certificate", request_certificate)
    monkeypatch.setattr(device, "_wait_for_replug", lambda *args, **kwargs: object())
    monkeypatch.setattr(device, "_read_last_error", lambda: None)
    monkeypatch.setattr(device, "_verify_card_pin", lambda *args, **kwargs: None)
    monkeypatch.setattr(device, "_wait_for_enrollment_mode", lambda *args, **kwargs: None)
    monkeypatch.setattr(device, "_enroll", lambda *args, **kwargs: b"vault-id")

    assert device._enroll_existing(envelope, "secret", "123456", license_file, app=APP_PIV) == b"vault-id"

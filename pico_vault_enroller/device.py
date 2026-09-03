import base64
import struct
import os
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x448
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fido2 import cbor
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin, PinProtocolV2
from fido2.hid import CAPABILITY, CTAPHID, CtapHidDevice

try:
    from fido2.pcsc import CtapPcscDevice
    from smartcard.System import readers as pcsc_readers
except ImportError:
    CtapPcscDevice = None
    pcsc_readers = None

from .crypto import (
    BACKEND_URL,
    _ENROLL_INFO,
    _FIDO_BACKUP_AID,
    _VAULT_ENROLL_BEGIN,
    _VAULT_ENROLL_FINISH,
    _VAULT_LABEL_MAX,
    _VAULT_STATUS,
    _VAULT_UNENROLL,
    _VENDOR_VAULT,
    _csr,
    _read_enrollment_json,
    _read_or_create,
    _request_certificate,
    _save,
)


APP_FIDO = "fido"
APP_OPENPGP = "openpgp"
APP_PIV = "piv"
APP_CHOICES = (APP_FIDO, APP_OPENPGP, APP_PIV)
APP_LABELS = {
    APP_FIDO: "FIDO PIN",
    APP_OPENPGP: "OpenPGP PW3",
    APP_PIV: "PIV PIN",
}
_OPENPGP_AID = bytes.fromhex("d27600012401")
_PIV_AID = bytes.fromhex("a000000308")
_VAULT_INS = 0xf2
_VERIFY_INS = 0x20


if CtapPcscDevice is not None:
    class _CtapPcscVendorDevice(CtapPcscDevice):
        def _select(self):
            apdu = b"\x00\xa4\x04\x00" + bytes([len(_FIDO_BACKUP_AID)]) + _FIDO_BACKUP_AID
            response, sw1, sw2 = self._chained_apdu_exchange(apdu)
            if (sw1, sw2) != (0x90, 0x00):
                raise ValueError("Pico-FIDO CCID applet selection failure")
            if response == b"U2F_V2":
                self._capabilities |= CAPABILITY.NMSG

        def call(self, cmd, data=b"", event=None, on_keepalive=None):
            if cmd != CTAPHID.VENDOR_FIRST + 1:
                return super().call(cmd, data, event, on_keepalive)
            response, sw1, sw2 = self._chain_apdus(0x00, CTAPHID.VENDOR_FIRST + 1, 0x00, 0x00, data)
            if (sw1, sw2) != (0x90, 0x00):
                raise RuntimeError(f"CCID vendor command failed: SW={sw1:02x}{sw2:02x}")
            return response
else:
    _CtapPcscVendorDevice = None


if CtapPcscDevice is not None:
    class _PcscApduDevice(CtapPcscDevice):
        def __init__(self, connection, name, aid):
            self._name = name
            self._capabilities = CAPABILITY(0)
            self.use_ext_apdu = False
            self.use_nfcctap_getresponse = True
            self._conn = connection
            self._aid = aid
            self._conn.connect()
            self._select()

        def _select(self):
            apdu = b"\x00\xa4\x04\x00" + bytes([len(self._aid)]) + self._aid
            response, sw1, sw2 = self._chained_apdu_exchange(apdu)
            if (sw1, sw2) != (0x90, 0x00):
                raise ValueError("Pico CCID applet selection failure")

        def send(self, ins, p1=0, p2=0, data=b""):
            response, sw1, sw2 = self._chain_apdus(0x00, ins, p1, p2, data)
            if (sw1, sw2) != (0x90, 0x00):
                raise RuntimeError(f"CCID APDU failed: SW={sw1:02x}{sw2:02x}")
            return response

        @classmethod
        def list_devices(cls, aid):
            if pcsc_readers is None:
                return
            for reader in pcsc_readers():
                connection = reader.createConnection()
                try:
                    yield cls(connection, reader.name, aid)
                except Exception:
                    try:
                        connection.disconnect()
                    except Exception:
                        pass
                    continue
else:
    _PcscApduDevice = None


def _vendor(device: CtapHidDevice, subcommand: int, params: dict | None = None, pin_protocol: PinProtocolV2 | None = None, pin_token: bytes | None = None) -> dict:
    arguments = {1: subcommand}
    raw_params = cbor.encode(params) if params is not None else b""
    if params is not None:
        arguments[2] = params
    if pin_protocol is not None and pin_token is not None:
        arguments[3] = pin_protocol.VERSION
        arguments[4] = pin_protocol.authenticate(pin_token, b"\xff" * 32 + b"\x0d" + bytes([subcommand]) + raw_params)
    response = device.call(CTAPHID.VENDOR_FIRST + 1, bytes([_VENDOR_VAULT]) + cbor.encode(arguments))
    if not response or response[0] != 0:
        raise RuntimeError(f"Pico-FIDO vendor error: 0x{response[0]:02x}" if response else "Pico-FIDO returned no response")
    return cbor.decode(response[1:]) if len(response) > 1 else {}


def _vault_apdu(device: _PcscApduDevice, subcommand: int, data: bytes = b"") -> bytes:
    return device.send(_VAULT_INS, subcommand, data=data)


def _enroll(device: CtapHidDevice, certificate: bytes, private: x448.X448PrivateKey, kvault: bytes, label: str, pin_protocol: PinProtocolV2 | None = None, pin_token: bytes | None = None, app: str = APP_FIDO) -> bytes:
    if app == APP_FIDO:
        begin = _vendor(device, _VAULT_ENROLL_BEGIN, pin_protocol=pin_protocol, pin_token=pin_token)
        device_public = begin.get(1, b"")
        challenge = begin.get(2, b"")
    else:
        begin = _vault_apdu(device, _VAULT_ENROLL_BEGIN)
        device_public = begin[:56]
        challenge = begin[56:88]
    if not isinstance(device_public, bytes) or len(device_public) != 56 or not isinstance(challenge, bytes) or len(challenge) != 32:
        raise ValueError("invalid enrollment challenge")
    certificate_public = x509.load_der_x509_certificate(certificate).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    info = _ENROLL_INFO + challenge + certificate_public + device_public
    shared = private.exchange(x448.X448PublicKey.from_public_bytes(device_public))
    session_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared)
    label_bytes = label.encode("utf-8")
    if len(label_bytes) > _VAULT_LABEL_MAX:
        raise ValueError(f"vault label must be at most {_VAULT_LABEL_MAX} UTF-8 bytes")
    enrollment_plain = kvault + bytes([len(label_bytes)]) + label_bytes
    nonce = os.urandom(12)
    encrypted = AESGCM(session_key).encrypt(nonce, enrollment_plain, info)
    packet = struct.pack(">H", len(certificate)) + certificate + nonce + encrypted
    if app == APP_FIDO:
        result = _vendor(device, _VAULT_ENROLL_FINISH, {1: packet}, pin_protocol, pin_token)
        vault_id = result.get(1, b"")
    else:
        vault_id = _vault_apdu(device, _VAULT_ENROLL_FINISH, packet)
    if not isinstance(vault_id, bytes) or len(vault_id) != 32:
        raise ValueError("invalid enrolled vault id")
    return vault_id


def _first_hid_device() -> CtapHidDevice | None:
    try:
        return next(CtapHidDevice.list_devices(), None)
    except OSError:
        return None


def _first_ccid_device(app: str = APP_FIDO):
    if _CtapPcscVendorDevice is None:
        return None
    try:
        if app == APP_FIDO:
            return next(_CtapPcscVendorDevice.list_devices(), None)
        return next(_PcscApduDevice.list_devices(_OPENPGP_AID if app == APP_OPENPGP else _PIV_AID), None)
    except Exception:
        return None


def _first_device(app: str = APP_FIDO):
    if app == APP_FIDO:
        return _first_hid_device() or _first_ccid_device(app)
    return _first_ccid_device(app)


def _wait_for_device(report=print, app: str = APP_FIDO):
    while True:
        device = _first_device(app)
        if device is not None:
            return device
        report(f"Waiting for Pico {app.upper()} CCID device..." if app != APP_FIDO else "Waiting for Pico-FIDO HID/CCID device...")
        time.sleep(1)


def _wait_for_replug(report=print, prompt=True, app: str = APP_FIDO):
    if prompt:
        input(f"Disconnect and reconnect the board, then press Enter for {APP_LABELS[app]} enrollment: ")
    else:
        report("Disconnect and reconnect the board")
    while True:
        device = _first_device(app)
        if device is not None:
            return device
        report(f"Waiting for Pico {app.upper()} CCID device..." if app != APP_FIDO else "Waiting for Pico-FIDO HID/CCID device...")
        time.sleep(1)


def _get_pin_token(device: CtapHidDevice, pin: str) -> tuple[PinProtocolV2, bytes]:
    if not pin:
        raise ValueError("Pico-FIDO PIN is required")
    ctap = Ctap2(device)
    protocol = PinProtocolV2()
    token = ClientPin(ctap, protocol).get_pin_token(pin, permissions=ClientPin.PERMISSION.AUTHENTICATOR_CFG)
    return protocol, token


def _verify_card_pin(device: _PcscApduDevice, app: str, pin: str) -> None:
    p2 = 0x83 if app == APP_OPENPGP else 0x80
    if app == APP_PIV:
        pin_bytes = pin.encode("ascii")
        if not 6 <= len(pin_bytes) <= 8:
            raise ValueError("PIV PIN must be 6 to 8 ASCII bytes")
        pin_bytes = pin_bytes.ljust(8, b"\xff")
    else:
        pin_bytes = pin.encode("utf-8")
    device.send(_VERIFY_INS, p2=p2, data=pin_bytes)


def _unenroll(device: CtapHidDevice, pin_protocol: PinProtocolV2 | None = None, pin_token: bytes | None = None, app: str = APP_FIDO) -> None:
    if app == APP_FIDO:
        _vendor(device, _VAULT_UNENROLL, pin_protocol=pin_protocol, pin_token=pin_token)
    else:
        _vault_apdu(device, _VAULT_UNENROLL)


def _wait_for_enrollment_mode(device: CtapHidDevice, report=print, app: str = APP_FIDO) -> None:
    report("Hold BOOTSEL continuously for 10 seconds; do not replug")
    while True:
        if app == APP_FIDO:
            status = _vendor(device, _VAULT_STATUS)
            ready = status.get(2, False)
            expired = isinstance(status.get(3), int) and status.get(3) >= 60000
        else:
            status = _vault_apdu(device, _VAULT_STATUS)
            ready = len(status) >= 3 and status[2] != 0
            expired = False
        if ready:
            report("Enrollment mode detected")
            return
        if expired:
            raise RuntimeError("board boot window expired; replug and try again")
        time.sleep(1)


def _enroll_existing(envelope: Path, passphrase: str, pin: str, license_file: Path, report=print, prompt: bool = True, app: str = APP_FIDO) -> bytes:
    if app not in APP_CHOICES:
        raise ValueError(f"unsupported app: {app}")
    _, stored = _read_enrollment_json(envelope, passphrase)
    if not license_file.is_file():
        raise ValueError("license file does not exist")
    kvault, private, label = _read_or_create(envelope, passphrase)
    encoded_certificate = stored.get("certificate", "")
    certificate = base64.b64decode(encoded_certificate) if encoded_certificate else b""
    cached = bool(certificate)
    reused = cached
    if not cached:
        report("Requesting backend certificate...")
        certificate, reused = _request_certificate(BACKEND_URL, license_file, _csr(private))
    certificate_public = x509.load_der_x509_certificate(certificate).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    expected_public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if certificate_public != expected_public:
        raise ValueError("backend certificate public key does not match the enrollment key")
    if not cached:
        _save(envelope, passphrase, kvault, private, certificate, label)
    report("Using existing certificate" if cached or reused else "Certificate issued")
    device = _wait_for_replug(report, prompt=prompt, app=app)
    if app == APP_FIDO:
        pin_protocol, pin_token = _get_pin_token(device, pin)
    else:
        if not pin:
            raise ValueError(f"{APP_LABELS[app]} is required")
        _verify_card_pin(device, app, pin)
        pin_protocol, pin_token = None, None
    _wait_for_enrollment_mode(device, report, app=app)
    return _enroll(device, certificate, private, kvault, label, pin_protocol, pin_token, app=app)


def _unenroll_existing(pin: str, report=print, app: str = APP_FIDO) -> None:
    if app not in APP_CHOICES:
        raise ValueError(f"unsupported app: {app}")
    report(f"Waiting for {APP_LABELS[app]} device...")
    device = _wait_for_device(report, app)
    if app == APP_FIDO:
        pin_protocol, pin_token = _get_pin_token(device, pin)
    else:
        if not pin:
            raise ValueError(f"{APP_LABELS[app]} is required")
        _verify_card_pin(device, app, pin)
        pin_protocol, pin_token = None, None
    report("Unenrolling vault...")
    _unenroll(device, pin_protocol, pin_token, app=app)
    report("Vault unenrolled; enrollment JSON kept")

import struct
import os
import time

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
except ImportError:
    CtapPcscDevice = None

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


def _enroll(device: CtapHidDevice, certificate: bytes, private: x448.X448PrivateKey, kvault: bytes, label: str, pin_protocol: PinProtocolV2, pin_token: bytes) -> bytes:
    begin = _vendor(device, _VAULT_ENROLL_BEGIN, pin_protocol=pin_protocol, pin_token=pin_token)
    device_public = begin.get(1, b"")
    challenge = begin.get(2, b"")
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
    result = _vendor(device, _VAULT_ENROLL_FINISH, {1: packet}, pin_protocol, pin_token)
    vault_id = result.get(1, b"")
    if not isinstance(vault_id, bytes) or len(vault_id) != 32:
        raise ValueError("invalid enrolled vault id")
    return vault_id


def _first_hid_device() -> CtapHidDevice | None:
    try:
        return next(CtapHidDevice.list_devices(), None)
    except OSError:
        return None


def _first_ccid_device():
    if _CtapPcscVendorDevice is None:
        return None
    try:
        return next(_CtapPcscVendorDevice.list_devices(), None)
    except Exception:
        return None


def _first_device():
    return _first_hid_device() or _first_ccid_device()


def _wait_for_device(report=print):
    while True:
        device = _first_device()
        if device is not None:
            return device
        report("Waiting for Pico-FIDO HID/CCID device...")
        time.sleep(1)


def _wait_for_replug(report=print, prompt=True):
    if prompt:
        input("Disconnect and reconnect the board, then press Enter: ")
    else:
        report("Disconnect and reconnect the board")
    while True:
        device = _first_device()
        if device is not None:
            return device
        report("Waiting for Pico-FIDO HID/CCID device...")
        time.sleep(1)


def _get_pin_token(device: CtapHidDevice, pin: str) -> tuple[PinProtocolV2, bytes]:
    if not pin:
        raise ValueError("Pico-FIDO PIN is required")
    ctap = Ctap2(device)
    protocol = PinProtocolV2()
    token = ClientPin(ctap, protocol).get_pin_token(pin, permissions=ClientPin.PERMISSION.AUTHENTICATOR_CFG)
    return protocol, token


def _unenroll(device: CtapHidDevice, pin_protocol: PinProtocolV2, pin_token: bytes) -> None:
    _vendor(device, _VAULT_UNENROLL, pin_protocol=pin_protocol, pin_token=pin_token)


def _wait_for_enrollment_mode(device: CtapHidDevice, report=print) -> None:
    report("Hold BOOTSEL continuously for 10 seconds; do not replug")
    while True:
        status = _vendor(device, _VAULT_STATUS)
        if status.get(2, False):
            report("Enrollment mode detected")
            return
        boottime = status.get(3)
        if isinstance(boottime, int) and boottime >= 60000:
            raise RuntimeError("board boot window expired; replug and try again")
        time.sleep(1)


def _enroll_existing(envelope: Path, passphrase: str, pin: str, license_file: Path, report=print, prompt: bool = True) -> bytes:
    _read_enrollment_json(envelope, passphrase)
    if not license_file.is_file():
        raise ValueError("license file does not exist")
    kvault, private, label = _read_or_create(envelope, passphrase)
    report("Requesting backend certificate...")
    certificate, reused = _request_certificate(BACKEND_URL, license_file, _csr(private))
    certificate_public = x509.load_der_x509_certificate(certificate).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    expected_public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if certificate_public != expected_public:
        raise ValueError("backend certificate public key does not match the enrollment key")
    _save(envelope, passphrase, kvault, private, certificate, label)
    report("Using existing certificate" if reused else "Certificate issued")
    device = _wait_for_replug(report, prompt=prompt)
    pin_protocol, pin_token = _get_pin_token(device, pin)
    _wait_for_enrollment_mode(device, report)
    return _enroll(device, certificate, private, kvault, label, pin_protocol, pin_token)


def _unenroll_existing(pin: str, report=print) -> None:
    report("Waiting for Pico-FIDO device...")
    device = _wait_for_device(report)
    pin_protocol, pin_token = _get_pin_token(device, pin)
    report("Unenrolling vault...")
    _unenroll(device, pin_protocol, pin_token)
    report("Vault unenrolled; enrollment JSON kept")

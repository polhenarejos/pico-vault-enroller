import base64
import getpass
import hashlib
import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed448, x448
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import NameOID, ObjectIdentifier


_AAD = b"PicoKeys Kvault envelope v1"
_ENROLL_INFO = b"PicoKeys Vault enrollment v1"
_VAULT_ID_DOMAIN = b"PicoKeys Vault ID v1"
_VAULT_X448_PUBLIC_KEY_OID = ObjectIdentifier("1.3.6.1.4.1.55555.1.2")
_VENDOR_VAULT = 0x05
_VAULT_STATUS = 0x01
_VAULT_ENROLL_BEGIN = 0x02
_VAULT_ENROLL_FINISH = 0x03
_VAULT_UNENROLL = 0x06
_VAULT_LABEL_MAX = 64
BACKEND_URL = "https://www.picokeys.com/pico/picokeyapp/"
_FIDO_BACKUP_AID = bytes.fromhex("b0000006472f0001")
_VAULT_ID_HEX_LENGTH = 12


def _default_path() -> Path:
    base = os.environ.get("APPDATA") if os.name == "nt" else os.environ.get("XDG_CONFIG_HOME")
    return Path(base or (Path.home() / ".config")) / "PicoKeys" / "vault" / "enrollment.json"


def _default_directory() -> Path:
    return _default_path().parent


def _label_slug(label: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", (label or "").strip()).strip("._-")[:40]


def _enrollment_path(directory: Path, kvault: bytes, label: str) -> Path:
    vault_id = _vault_id(kvault).hex()[:_VAULT_ID_HEX_LENGTH]
    suffix = f"-{_label_slug(label)}" if _label_slug(label) else ""
    return directory / f"enrollment-{vault_id}{suffix}.json"


def _derive(passphrase: str, salt: bytes) -> bytes:
    return Argon2id(salt=salt, length=32, iterations=3, lanes=4, memory_cost=64 * 1024).derive(passphrase.encode())


def _vault_id(kvault: bytes) -> bytes:
    return hashlib.sha256(_VAULT_ID_DOMAIN + kvault).digest()


def _read_or_create(path: Path | None, passphrase: str, label: str | None = None, create_new: bool = False) -> tuple[bytes, x448.X448PrivateKey, str]:
    if path is not None and path.is_file() and not create_new:
        value, stored = _read_enrollment_json(path, passphrase)
        kvault = base64.b64decode(stored["kvault"])
        private = x448.X448PrivateKey.from_private_bytes(base64.b64decode(stored["x448_private"]))
        if len(kvault) != 32 or _vault_id(kvault).hex() != stored["vault_id"]:
            raise ValueError("invalid enrollment envelope")
        return kvault, private, str(stored.get("label") or value.get("label") or "")
    confirm = getpass.getpass("Confirm vault passphrase: ")
    if not passphrase or passphrase != confirm:
        raise ValueError("passphrases do not match")
    if label is None:
        label = input("Vault label (optional): ").strip()
    return os.urandom(32), x448.X448PrivateKey.generate(), label.strip()


def _read_enrollment_json(path: Path, passphrase: str) -> tuple[dict, dict]:
    value = json.loads(path.read_text(encoding="utf-8"))
    salt = base64.b64decode(value["salt"])
    nonce = base64.b64decode(value["nonce"])
    plain = AESGCM(_derive(passphrase, salt)).decrypt(nonce, base64.b64decode(value["ciphertext"]), _AAD)
    stored = json.loads(plain.decode("utf-8"))
    return value, stored


def _save(path: Path, passphrase: str, kvault: bytes, private: x448.X448PrivateKey, certificate: bytes, label: str = "") -> None:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    vault_id = _vault_id(kvault).hex()
    plain = json.dumps({"version": 1, "label": label, "kvault": base64.b64encode(kvault).decode(), "x448_private": base64.b64encode(private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())).decode(), "certificate": base64.b64encode(certificate).decode(), "vault_id": vault_id}, separators=(",", ":")).encode()
    ciphertext = AESGCM(_derive(passphrase, salt)).encrypt(nonce, plain, _AAD)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"version": 1, "label": label, "vault_id": vault_id, "salt": base64.b64encode(salt).decode(), "nonce": base64.b64encode(nonce).decode(), "ciphertext": base64.b64encode(ciphertext).decode(), "public_key": base64.b64encode(public).decode()}, indent=2), encoding="utf-8")
    if os.name != "nt":
        os.chmod(path, 0o600)


def _csr(private: x448.X448PrivateKey) -> bytes:
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    signer = ed448.Ed448PrivateKey.generate()
    request = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PicoKeys Vault")])).add_extension(x509.UnrecognizedExtension(_VAULT_X448_PUBLIC_KEY_OID, public), critical=False).sign(signer, algorithm=None)
    return request.public_bytes(serialization.Encoding.PEM)


def _request_certificate(backend_url: str, license_file: Path, csr: bytes) -> tuple[bytes, bool]:
    body = json.dumps({"csr": csr.decode("ascii"), "license": base64.b64encode(license_file.read_bytes()).decode("ascii")}).encode("utf-8")
    request = urllib.request.Request(f"{backend_url.rstrip('/')}/vault-cert/", data=body, headers={"Content-Type": "application/json", "Accept": "application/json", "User-Agent": "PicoKeyApp/1.0", "Referer": "https://www.picokeys.com/pico/picokeyapp/"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.loads(response.read().decode())
    except urllib.error.HTTPError as error:
        body = error.read().decode(errors="replace") or "<empty response>"
        raise RuntimeError(f"certificate request failed ({error.code}) at {request.full_url}: {body}") from error
    certificate = payload.get("certificate")
    if not isinstance(certificate, str):
        raise RuntimeError(f"certificate request failed: {payload}")
    return x509.load_pem_x509_certificate(certificate.encode()).public_bytes(serialization.Encoding.DER), bool(payload.get("reused", False))


def _create_new_envelope(license_file: Path, passphrase: str, confirmation: str, label: str, directory: Path | None = None, envelope: Path | None = None) -> Path:
    if not passphrase or passphrase != confirmation:
        raise ValueError("passphrases do not match")
    if not license_file.is_file():
        raise ValueError("license file does not exist")
    kvault = os.urandom(32)
    private = x448.X448PrivateKey.generate()
    path = envelope or _enrollment_path(directory or _default_directory(), kvault, label)
    _save(path, passphrase, kvault, private, b"", label)
    return path

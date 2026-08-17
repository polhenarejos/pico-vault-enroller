# PicoKeys Vault Enroller

`pico-vault-enroller` is the standalone host-side tool for provisioning a
Pico-FIDO Vault. It creates or opens an encrypted recovery envelope, obtains a
Vault certificate from the PicoKeys service, and performs the PIN- and
button-authorized enrollment ceremony over HID or CCID.

This tool handles the plaintext `Kvault` during enrollment. Treat the computer
running it as trusted and keep the resulting enrollment JSON and passphrase
safe. The 1.0 release is not a replacement for a tested backup and recovery
procedure.

## Relationship to Pico-FIDO

The enroller is the host-side companion to the firmware in the
[Pico-FIDO project](https://github.com/polhenarejos/pico-fido). Install a
Vault-capable firmware build from that project before using this repository;
the enroller does not flash or upgrade a board. Use the firmware repository's
[README](https://github.com/polhenarejos/pico-fido#readme) and
[releases](https://github.com/polhenarejos/pico-fido/releases) for board support,
firmware images, build instructions, and firmware-specific security notes.

The device-bound export and import model provisioned by this tool is described
in Pol Henarejos, [*Vaulted Passkeys: A Device-Bound Proposal for Authenticated
Credential Export and Import*](https://arxiv.org/abs/2608.13806).

## Requirements

- Python 3.10 or newer.
- A Pico-FIDO firmware build with Vault enrollment support.
- A valid PicoKeys license file.
- The board PIN and physical access to its `BOOTSEL` button.
- Network access to `https://www.picokeys.com/pico/picokeyapp/` while requesting
  the certificate.
- A working USB HID stack. CCID/PCSC access is also supported when `pyscard`
  and the platform smart-card service are available.

The GUI uses the Python standard-library `tkinter` module. On some Linux
distributions it is installed as a separate system package.

## Install from a checkout

Use a virtual environment and install the project in editable mode while
developing:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

For a normal user install, omit `-e`. The package declares the required
`cryptography`, `fido2`, and `pyscard` dependencies.

## CLI commands

The 1.0 program is the `pico_vault_enroller` package. After installation use
`pico_vault_enroller`; from a checkout use `python -m pico_vault_enroller`.

```sh
pico_vault_enroller help
pico_vault_enroller version
pico_vault_enroller create --license-file /path/to/license.json --label "office backup"
pico_vault_enroller enroll --license-file /path/to/license.bin --envelope /path/to/enrollment.json
pico_vault_enroller unenroll
```

`create` makes the encrypted recovery envelope. It prompts for the passphrase,
confirmation, and optional label when those values are not supplied. `enroll`
requests the certificate and performs the board ceremony. `unenroll` removes
the Vault key and certificate from the board and asks for an explicit `yes`
confirmation unless `--yes` is supplied.

Every GUI field has an equivalent CLI option. For example, the create form's
license file, passphrase, confirmation, label, and output file are supplied as
`--license-file`, `--passphrase`, `--confirm-passphrase`, `--label`, and
`--envelope`:

```sh
pico_vault_enroller create \
  --license-file license.json \
  --passphrase "..." \
  --confirm-passphrase "..." \
  --label office \
  --envelope enrollment.json
pico_vault_enroller enroll --license-file license.json --envelope enrollment.json --passphrase "..." --pin "123456"
pico_vault_enroller gui --license-file license.json --envelope enrollment.json --passphrase "..." --pin "123456"
```

The complete option set is shown by `pico_vault_enroller help create`,
`pico_vault_enroller help enroll`, and `pico_vault_enroller help gui`. Avoid putting passphrases or PINs directly on
the command line because shells and process listings may retain them; omit
those flags to receive secure prompts.

Global help and version flags are also available:

```sh
pico_vault_enroller --help
pico_vault_enroller --version
```

## Quick start (GUI)

Start the guided interface with:

```sh
pico_vault_enroller gui
```

Select the license file, create or select an enrollment JSON, unlock it with
its passphrase, and choose **Enroll vault**. The GUI also exposes **Unenroll
vault**, which removes the Vault key and certificate from the board but keeps
the local enrollment JSON for later use.

See [the end-to-end tutorial](docs/tutorial.md) for a first enrollment and
[the operations guide](docs/operations.md) for backup, replacement-board, and
unenrollment procedures.

The implementation lives in the `pico_vault_enroller` package: `cli.py` owns
command parsing, `gui.py` the optional interface, `device.py` the Pico-FIDO
ceremony, and `crypto.py` the encrypted envelope and certificate helpers.

## Enrollment files

By default, files are stored below:

| Platform | Default directory |
| --- | --- |
| Linux/macOS | `$XDG_CONFIG_HOME/PicoKeys/vault`, or `~/.config/PicoKeys/vault` |
| Windows | `%APPDATA%\\PicoKeys\\vault` |

New files are named `enrollment-<vault-id-prefix>-<label>.json`. The JSON
contains an AES-GCM ciphertext. The plaintext inside it contains the Vault
root key, the enroller X448 private key, the certificate, and the label. The
license file is not parsed or copied into the envelope; it is sent as opaque
bytes to the backend during enrollment. The passphrase is never sent to the
backend or the board.

Back up the entire JSON file and its passphrase independently. A copy of the
JSON without its passphrase is unusable; a passphrase without the JSON cannot
recover the Vault. Do not commit enrollment files to source control or paste
them into issue trackers.

## Compatibility and scope

- The current wire profile requires the backend-issued certificate. There is
  no offline or anonymous enrollment mode.
- The certificate is checked against the generated X448 public key before the
  envelope is updated.
- The tool does not flash firmware, change the board PIN, export credentials,
  or import Vault blobs.
- The CLI supports create, enrollment, and unenrollment; the GUI remains
  available for interactive workflows.
- The backend URL and certificate protocol are part of this release; there is
  no command-line endpoint override.

## Troubleshooting

**No device is found**

Reconnect the board directly to the computer, close applications that may have
claimed the FIDO interface, and verify that the firmware exposes HID or CCID.
On Linux, check the udev permissions for the device. For CCID, confirm that a
PC/SC service is running and that `pyscard` installed successfully.

**PIN authentication fails**

Check the PIN and retry with the board freshly connected. Repeated failures
follow the firmware's PIN retry policy; the enroller does not bypass it.

**The enrollment window expires**

Start again and hold `BOOTSEL` continuously for the full ten seconds. The
board must remain connected after the reconnect step. The firmware's window is
finite, so do not pause between prompts.

**Certificate request fails**

Check network access, the license file, and the system clock. License
validation and certificate issuance are performed by the configured PicoKeys
backend.

**The passphrase is lost**

The envelope is intentionally unrecoverable without its passphrase. If the
board and the recovery envelope are both unavailable, the Vault credentials
must be re-enrolled into a new domain.

## Development checks

```sh
python -m compileall -q pico_vault_enroller
python -m pytest
python -m pip install --upgrade build
python -m build
```

The hardware ceremony requires a real supported board and is not covered by a
pure host-only test run.

## License

Copyright © Pol Henarejos and contributors. This project is licensed under the GNU
Affero General Public License, version 3 or later. See [LICENSE](LICENSE).

The companion firmware is maintained separately in
[polhenarejos/pico-fido](https://github.com/polhenarejos/pico-fido).

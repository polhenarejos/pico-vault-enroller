# First Vault enrollment

This tutorial assumes a supported Pico-FIDO board is already running Vault
firmware and that you have received a license file. The command-line path is
shown first; the GUI performs the same ceremony.

If the board is not ready, start with the
[Pico-FIDO firmware repository](https://github.com/polhenarejos/pico-fido). Its
[README](https://github.com/polhenarejos/pico-fido#readme) covers board
selection, firmware downloads, and building from source. This repository only
installs the host enroller.

## 1. Install in an isolated environment

```sh
git clone https://github.com/polhenarejos/pico-vault-enroller.git
cd pico-vault-enroller
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
```

Confirm that the command is available:

```sh
pico_vault_enroller help
pico_vault_enroller version
```

## 2. Create the recovery envelope

Connect the board and keep the license file available. Start enrollment:

```sh
pico_vault_enroller create \
  --license-file /secure/path/picokeys-license.json \
  --label "office backup"
```

Choose a strong, unique passphrase when prompted. The tool writes an encrypted
JSON file below the platform's PicoKeys configuration directory. Record the
path it prints or find it with:

```sh
find "$HOME/.config/PicoKeys/vault" -name 'enrollment-*.json' -print
```

On Windows, use `%APPDATA%\\PicoKeys\\vault` instead. If you already have an
enrollment file, skip `create` and pass it to `enroll` with `--envelope PATH`.

## 3. Complete the board ceremony

Start the ceremony with:

```sh
pico_vault_enroller enroll \
  --license-file /secure/path/picokeys-license.json \
  --envelope /secure/path/enrollment.json
```

The enroller sends the license file as opaque bytes to the backend. The host
does not parse, decrypt, or inspect the license. The backend returns a
certificate, which the enroller verifies contains the generated X448 public
key. It then prompts you to
disconnect and reconnect the board. After reconnecting:

1. Enter the board's Pico-FIDO PIN.
2. When the tool says it is waiting for enrollment mode, hold `BOOTSEL`.
3. Keep holding it for 10 seconds. Do not unplug the board during the hold.
4. Release the button when enrollment mode is detected.

The command prints a 64-character Vault ID. Keep this ID with your inventory
record; it identifies the Vault domain but does not replace the encrypted
recovery file.

## 4. Protect the recovery material

After a successful enrollment, make two independent backups:

- the `enrollment-*.json` file;
- the passphrase, stored through a separate protected channel.

Do not place either item in the repository, shell history, support ticket, or
untrusted cloud storage. The JSON is encrypted, but it still reveals metadata
such as the Vault ID and label.

## 5. Verify the operational path

Before relying on the board, verify the workflow your deployment needs:

- reconnect and unlock the same enrollment JSON;
- perform one supported Vault export/import test with the main Pico-FIDO tools;
- confirm that the saved Vault ID matches the inventory record;
- document who can access the board PIN and who can access the recovery
  passphrase.

The enroller itself does not export or import credentials. It only provisions
the Vault key and certificate used by the firmware's Vault feature.

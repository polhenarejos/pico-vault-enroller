# Release checklist

Run the checklist from a clean checkout of the enroller repository.

The enroller is released alongside the companion
[Pico-FIDO firmware repository](https://github.com/polhenarejos/pico-fido).
Record the compatible firmware commit or release in the release notes; a
Python package release alone does not make an incompatible firmware build
enrollable.

## Source and metadata

- [ ] Update `__version__` in `pico_vault_enroller/__init__.py`.
- [ ] Add a dated entry to `CHANGELOG.md`.
- [ ] Confirm `README.md`, tutorials, and compatibility notes match the
      firmware and backend being released.
- [ ] Confirm the license and repository URLs are correct.
- [ ] Confirm no license files, enrollment JSON files, certificates, PINs, or
      passphrases are present in the working tree.

## Automated checks

```sh
python -m compileall -q pico_vault_enroller tests
python -m pytest
python -m build
python -m pip install --force-reinstall dist/*.whl
pico_vault_enroller help
pico_vault_enroller version
```

Inspect the wheel and source archive before publishing:

```sh
python -m zipfile -l dist/*.whl
tar -tf dist/*.tar.gz
```

The distributions should contain the package modules, metadata, README, and license;
they must not contain local virtual environments or test artifacts.

## Hardware acceptance

On each supported transport that is advertised for the release:

1. Create a new envelope with a test license.
2. Enroll a board and record the Vault ID.
3. Re-enroll the same envelope on a replacement board and confirm the Vault ID
   is unchanged.
4. Unenroll the board through the GUI and confirm the local JSON remains.
5. Verify that a wrong passphrase, wrong PIN, expired button window, and
   certificate/public-key mismatch fail without replacing a valid envelope.

Record firmware version, board model, operating system, Python version,
transport (HID or CCID), and backend endpoint in the release evidence.

## Publishing

Tag the release from the commit containing the source, changelog, and generated
artifacts. Upload the wheel and source archive together with SHA-256 checksums.
Keep the release notes explicit about the required firmware version and the
fact that the current profile requires online certificate issuance.

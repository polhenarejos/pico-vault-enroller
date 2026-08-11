# Security policy

## Scope

Please report vulnerabilities in the enroller, its packaging, or the
enrollment protocol implementation. Do not include real license files,
enrollment JSON files, certificates, PINs, passphrases, or credential blobs in
a report.

The enroller is part of the PicoKeys Vault path. Firmware vulnerabilities
belong in the [Pico-FIDO repository](https://github.com/polhenarejos/pico-fido)
unless the issue demonstrably depends on this host tool.

## Reporting

Use a private GitHub security advisory for the
[pico-vault-enroller repository](https://github.com/polhenarejos/pico-vault-enroller/security/advisories/new)
when available. Otherwise contact the maintainers through the private channel
listed by the Pico-FIDO project and include:

- affected version or commit;
- operating system and Python version;
- whether HID or CCID was used;
- a minimal reproduction without secrets;
- impact and any known mitigations.

Do not open a public issue for an unpatched vulnerability.

## Supported versions

Only the latest release on the default branch is currently supported. Upgrade
the host tool and compatible Pico-FIDO firmware together when a security fix
requires a protocol change.

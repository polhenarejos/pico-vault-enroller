# Security policy

## Scope

Please report vulnerabilities in the enroller, its packaging, or the
enrollment protocol implementation, including its FIDO, OpenPGP, and PIV
application handling. Do not include real license files, enrollment JSON
files, certificates, FIDO PINs, OpenPGP PW3 passwords, PIV PINs, passphrases,
or credential blobs in a report.

FIDO enrollment uses HID or CCID. OpenPGP and PIV enrollment use CCID through
the platform's PC/SC service.

The enroller is part of the PicoKeys Vault path. Firmware vulnerabilities
belong in the relevant firmware repository, such as the
[Pico-FIDO repository](https://github.com/polhenarejos/pico-fido) or the
Pico-OpenPGP project, unless the issue demonstrably depends on this host tool.

## Reporting

Use a private GitHub security advisory for the
[pico-vault-enroller repository](https://github.com/polhenarejos/pico-vault-enroller/security/advisories/new)
when available. Otherwise contact the maintainers through the private channel
listed by the relevant firmware project and include:

- affected version or commit;
- operating system and Python version;
- selected application (FIDO, OpenPGP, or PIV) and whether HID or CCID/PCSC was used;
- a minimal reproduction without secrets;
- impact and any known mitigations.

Do not open a public issue for an unpatched vulnerability.

## Supported versions

Only the latest release on the default branch is currently supported. Upgrade
the host tool and compatible PicoKeys firmware together when a security fix
requires a protocol change.

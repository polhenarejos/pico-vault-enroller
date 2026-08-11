# Changelog

## 1.0.0 - 2026-08-12

- Added the `pico_vault_enroller` package and the `create`, `enroll`,
  `unenroll`, `help`, `gui`, and `version` commands.
- Added explicit CLI flags for every GUI field, including license file,
  passphrases, label, enrollment JSON, and PIN.
- Added release documentation, tutorials, and operational guidance.
- Corrected the `fido2` PIN import path used by the supported API.
- The encrypted envelope is updated only after the backend certificate is
  checked against the generated X448 public key.
- Enrollment failures now return a non-zero CLI exit status.
- Organized the implementation into separate CLI, GUI, device, and crypto modules.
- License files are now opaque to the host and are submitted to the backend for
  validation and certificate issuance.

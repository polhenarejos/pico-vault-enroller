# Vault operations

## Re-enroll an existing Vault on a replacement board

1. Flash the replacement board with a Vault-capable firmware build.
2. Keep the original `enrollment-*.json` and its passphrase available.
3. Run the enroller with `--envelope` pointing to that file.
4. Complete the PIN and `BOOTSEL` ceremony on the replacement board.
5. Verify that the printed Vault ID is the expected ID.

The replacement board receives the same `Kvault`, so it remains in the same
Vault domain. A new envelope created with `create` does not have this
property.

## Unenroll a board

Use the GUI, select the enrollment JSON, unlock it, enter the board PIN, and
choose **Unenroll vault**. Confirm the warning. The board's Vault key and
certificate are removed; the local JSON is deliberately retained so the Vault
can be enrolled again later.

Unenrollment is a device operation. Deleting the local JSON alone does not
remove the key from a board, and unenrolling the board does not destroy the
local recovery copy.

## Rotate or retire a Vault

Run `pico_vault_enroller create` only when you need a new Vault domain.
Re-enroll the intended board(s), update inventory and recovery records, and
retire the old board and envelope according to your key-management policy.
Do not overwrite the old JSON until you have verified the new domain.

## Recovery expectations

The passphrase-protected JSON is the host-side recovery copy of `Kvault`; it is
not a second PIN and cannot be reset by the board. If the passphrase is lost,
the ciphertext cannot be decrypted. If both the board copy and recovery copy
are lost, credentials in that Vault domain cannot be restored.

## Release and incident handling

If a recovery JSON or passphrase may have been exposed, treat the Vault as
compromised. Preserve logs and inventory information, unenroll affected
boards where possible, create a new Vault domain, and re-register credentials
according to your relying-party recovery process. Do not attempt to repair an
exposed envelope by editing its JSON fields.

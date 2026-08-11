import argparse
import getpass
import sys
from pathlib import Path

from .crypto import _create_new_envelope
from .device import _enroll_existing, _unenroll_existing
from .gui import gui_main
from . import __version__


def _path(value: str | Path | None) -> Path | None:
    return Path(value) if value is not None else None


def _create_command(args: argparse.Namespace) -> int:
    license_file = _path(args.license_file)
    if license_file is None:
        raise ValueError("create requires --license-file")
    passphrase = args.passphrase if args.passphrase is not None else getpass.getpass("Vault passphrase: ")
    confirmation = args.confirm_passphrase if args.confirm_passphrase is not None else getpass.getpass("Confirm vault passphrase: ")
    label = args.label if args.label is not None else input("Vault label (optional): ").strip()
    envelope = _path(args.envelope)
    path = _create_new_envelope(license_file, passphrase, confirmation, label, _path(args.directory), envelope)
    print(f"Created enrollment envelope: {path}")
    return 0


def _enroll_command(args: argparse.Namespace) -> int:
    envelope = _path(args.envelope)
    if envelope is None:
        raise ValueError("enroll requires --envelope")
    passphrase = args.passphrase if args.passphrase is not None else getpass.getpass("Vault passphrase: ")
    pin = args.pin if args.pin is not None else getpass.getpass("Pico-FIDO PIN: ")
    vault_id = _enroll_existing(envelope, passphrase, pin, _path(args.license_file), prompt=not bool(args.no_replug_prompt))
    print(f"Enrolled vault: {vault_id.hex()}", flush=True)
    return 0


def _unenroll_command(args: argparse.Namespace) -> int:
    pin = args.pin if args.pin is not None else getpass.getpass("Pico-FIDO PIN: ")
    if not args.yes and input("Remove the Vault key and certificate from the board? Type 'yes' to continue: ").strip().lower() != "yes":
        print("Unenrollment cancelled")
        return 0
    _unenroll_existing(pin)
    return 0


def _build_parser() -> tuple[argparse.ArgumentParser, dict[str, argparse.ArgumentParser]]:
    parser = argparse.ArgumentParser(prog="pico_vault_enroller", description="Create and enroll a PicoKeys Vault")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command")
    command_parsers = {}

    create = commands.add_parser("create", help="create an encrypted enrollment envelope")
    create.add_argument("--license-file")
    create.add_argument("--passphrase")
    create.add_argument("--confirm-passphrase")
    create.add_argument("--label")
    create.add_argument("--envelope", help="write to this exact JSON path")
    create.add_argument("--directory", help="directory for an automatically named envelope")
    command_parsers["create"] = create

    enroll = commands.add_parser("enroll", help="enroll an existing envelope on a board")
    enroll.add_argument("--envelope")
    enroll.add_argument("--license-file", required=True, help="opaque license file sent to the backend")
    enroll.add_argument("--passphrase")
    enroll.add_argument("--pin")
    enroll.add_argument("--no-replug-prompt", action="store_true", default=None)
    command_parsers["enroll"] = enroll

    unenroll = commands.add_parser("unenroll", help="remove the Vault key from a board")
    unenroll.add_argument("--pin")
    unenroll.add_argument("--yes", action="store_true", default=None)
    command_parsers["unenroll"] = unenroll

    gui = commands.add_parser("gui", help="start the guided graphical interface")
    gui.add_argument("--license-file")
    gui.add_argument("--create-passphrase")
    gui.add_argument("--create-confirmation")
    gui.add_argument("--create-label")
    gui.add_argument("--envelope")
    gui.add_argument("--passphrase")
    gui.add_argument("--pin")
    command_parsers["gui"] = gui

    help_parser = commands.add_parser("help", help="show help for a command")
    help_parser.add_argument("topic", nargs="?", choices=sorted(command_parsers))
    command_parsers["help"] = help_parser
    version_parser = commands.add_parser("version", help="print the release version")
    command_parsers["version"] = version_parser
    return parser, command_parsers


def main(argv=None):
    parser, command_parsers = _build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    if args.command == "help":
        if args.topic:
            command_parsers[args.topic].print_help()
        else:
            parser.print_help()
        return 0
    if args.command == "version":
        print(__version__)
        return 0
    try:
        if args.command == "create":
            return _create_command(args)
        if args.command == "enroll":
            return _enroll_command(args)
        if args.command == "unenroll":
            return _unenroll_command(args)
        if args.command == "gui":
            return gui_main(_path(args.license_file), args.create_passphrase or "", args.create_confirmation or "", args.create_label or "", _path(args.envelope), args.passphrase or "", args.pin or "")
        raise ValueError(f"unsupported command: {args.command}")
    except KeyboardInterrupt:
        print("Cancelled", file=sys.stderr)
        return 130
    except Exception as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

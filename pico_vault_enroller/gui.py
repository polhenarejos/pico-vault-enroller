import os
import threading
from pathlib import Path

from .crypto import _create_new_envelope, _default_directory, _read_enrollment_json
from .device import _enroll_existing, _unenroll_existing


def _open_enrollment_directory() -> None:
    directory = _default_directory()
    directory.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        os.startfile(str(directory))
    else:
        import webbrowser
        webbrowser.open(directory.as_uri())


def gui_main(license_file: Path | None = None, create_passphrase: str = "", create_confirmation: str = "", create_label: str = "", envelope: Path | None = None, passphrase: str = "", pin: str = ""):
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    root = tk.Tk()
    root.title("PicoKeys Vault Enroller")
    root.geometry("760x400")
    root.minsize(700, 380)
    asset_root = Path(__file__).resolve().parent.parent / "picokeyapp" / "assets"
    try:
        root.iconbitmap(str(asset_root / "icon.ico"))
    except Exception:
        pass
    license_var = tk.StringVar(value=str(license_file or ""))
    create_passphrase_var = tk.StringVar(value=create_passphrase)
    create_confirmation_var = tk.StringVar(value=create_confirmation)
    create_label_var = tk.StringVar(value=create_label)
    enroll_path_var = tk.StringVar(value=str(envelope or ""))
    enroll_id_var = tk.StringVar(value="Not selected")
    enroll_label_var = tk.StringVar(value="Not selected")
    enroll_passphrase_var = tk.StringVar(value=passphrase)
    enroll_pin_var = tk.StringVar(value=pin)
    status_var = tk.StringVar(value="Ready.")

    form = ttk.Frame(root, padding=10)
    form.pack(fill="both", expand=True)
    form.columnconfigure(0, weight=1)
    form.columnconfigure(1, weight=1)
    form.rowconfigure(1, weight=1)

    header = ttk.Frame(form)
    header.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 6))
    try:
        logo = tk.PhotoImage(file=str(asset_root / "pico-keys-256.png"))
        logo = logo.subsample(max(1, logo.width() // 64), max(1, logo.height() // 64))
        logo_label = tk.Label(header, image=logo)
        logo_label.image = logo
        logo_label.pack(side="left", padx=(0, 10))
    except Exception:
        pass
    ttk.Label(header, text="PicoKeys Vault Enroller", font=("TkDefaultFont", 16, "bold")).pack(side="left")

    create_box = ttk.LabelFrame(form, text="Create new vault", padding=8)
    create_box.grid(row=1, column=0, sticky="nsew", padx=(0, 6), pady=4)
    create_box.columnconfigure(1, weight=1)
    ttk.Label(create_box, text="License file").grid(row=0, column=0, sticky="w", pady=4)
    ttk.Entry(create_box, textvariable=license_var, width=58).grid(row=0, column=1, sticky="ew", pady=4)
    ttk.Button(create_box, text="Browse", command=lambda: license_var.set(filedialog.askopenfilename(filetypes=[("License files", "*")]))).grid(row=0, column=2, padx=(8, 0), pady=4)
    ttk.Label(create_box, text="Vault passphrase").grid(row=1, column=0, sticky="w", pady=4)
    ttk.Entry(create_box, textvariable=create_passphrase_var, show="*", width=58).grid(row=1, column=1, columnspan=2, sticky="ew", pady=4)
    ttk.Label(create_box, text="Confirm passphrase").grid(row=2, column=0, sticky="w", pady=4)
    ttk.Entry(create_box, textvariable=create_confirmation_var, show="*", width=58).grid(row=2, column=1, columnspan=2, sticky="ew", pady=4)
    ttk.Label(create_box, text="Vault label (optional)").grid(row=3, column=0, sticky="w", pady=4)
    ttk.Entry(create_box, textvariable=create_label_var, width=58).grid(row=3, column=1, columnspan=2, sticky="ew", pady=4)

    def report(message: str):
        root.after(0, lambda: status_var.set(message))

    def load_enrollment_info():
        path = Path(enroll_path_var.get()) if enroll_path_var.get() else None
        enroll_id_var.set("Not selected")
        enroll_label_var.set("Not selected")
        if not path or not path.is_file() or not enroll_passphrase_var.get():
            return
        try:
            value, stored = _read_enrollment_json(path, enroll_passphrase_var.get())
            enroll_id_var.set(str(stored.get("vault_id") or value.get("vault_id") or "Unavailable"))
            enroll_label_var.set(str(stored.get("label") or value.get("label") or "(no label)"))
        except Exception as error:
            enroll_id_var.set("Unlock failed")
            enroll_label_var.set("")

    def select_enrollment():
        path = filedialog.askopenfilename(initialdir=_default_directory(), filetypes=[("JSON files", "*.json")])
        if path:
            enroll_path_var.set(path)
            load_enrollment_info()

    def unlock_enrollment():
        if not enroll_path_var.get() or not enroll_passphrase_var.get():
            report("Unlock failed")
            return
        load_enrollment_info()
        if enroll_id_var.get() == "Unlock failed":
            report("Unlock failed")
        else:
            report("Enrollment JSON unlocked")

    def create_new():
        try:
            if not license_var.get():
                raise ValueError("license file is required")
            path = _create_new_envelope(Path(license_var.get()), create_passphrase_var.get(), create_confirmation_var.get(), create_label_var.get())
            enroll_path_var.set(str(path))
            enroll_passphrase_var.set(create_passphrase_var.get())
            load_enrollment_info()
            report(f"Created {path.name}")
        except Exception as error:
            messagebox.showerror("Create vault failed", str(error))

    def enroll():
        envelope_path = Path(enroll_path_var.get()) if enroll_path_var.get() else None
        license_path = Path(license_var.get()) if license_var.get() else None
        passphrase = enroll_passphrase_var.get()
        pin = enroll_pin_var.get()
        if not envelope_path or not license_path or not passphrase or not pin:
            messagebox.showerror("Enrollment", "License file, enrollment JSON, passphrase, and PIN are required")
            return
        def worker():
            try:
                vault_id = _enroll_existing(envelope_path, passphrase, pin, license_path, report=report, prompt=False)
                report(f"Enrolled vault: {vault_id.hex()}")
            except Exception as error:
                report(f"Enrollment failed: {error}")
        threading.Thread(target=worker, daemon=True).start()

    def unenroll():
        pin = enroll_pin_var.get()
        if not pin:
            messagebox.showerror("Unenroll vault", "Pico-FIDO PIN is required")
            return
        if not messagebox.askyesno("Unenroll vault", "Remove the vault key and certificate from the board? The enrollment JSON will be kept."):
            return
        def worker():
            try:
                _unenroll_existing(pin, report=report)
            except Exception as error:
                report(f"Unenrollment failed: {error}")
        threading.Thread(target=worker, daemon=True).start()

    ttk.Button(create_box, text="Create new kvault", command=create_new).grid(row=4, column=0, columnspan=3, sticky="w", pady=(10, 0))

    enroll_box = ttk.LabelFrame(form, text="Enroll existing vault", padding=8)
    enroll_box.grid(row=1, column=1, sticky="nsew", padx=(6, 0), pady=4)
    enroll_box.columnconfigure(1, weight=1)
    ttk.Label(enroll_box, text="Enrollment JSON").grid(row=0, column=0, sticky="w", pady=4)
    ttk.Entry(enroll_box, textvariable=enroll_path_var, width=58, state="readonly").grid(row=0, column=1, sticky="ew", pady=4)
    ttk.Button(enroll_box, text="Select", command=select_enrollment).grid(row=0, column=2, padx=(8, 0), pady=4)
    ttk.Label(enroll_box, text="Vault passphrase").grid(row=1, column=0, sticky="w", pady=4)
    enroll_passphrase_entry = ttk.Entry(enroll_box, textvariable=enroll_passphrase_var, show="*", width=58)
    enroll_passphrase_entry.grid(row=1, column=1, sticky="ew", pady=4)
    enroll_passphrase_entry.bind("<Return>", lambda _: unlock_enrollment())
    ttk.Button(enroll_box, text="Unlock JSON", command=unlock_enrollment).grid(row=1, column=2, padx=(8, 0), pady=4)
    ttk.Label(enroll_box, text="Vault ID").grid(row=2, column=0, sticky="w", pady=4)
    ttk.Entry(enroll_box, textvariable=enroll_id_var, state="readonly").grid(row=2, column=1, columnspan=2, sticky="ew", pady=4)
    ttk.Label(enroll_box, text="Vault label").grid(row=3, column=0, sticky="w", pady=4)
    ttk.Entry(enroll_box, textvariable=enroll_label_var, state="readonly").grid(row=3, column=1, columnspan=2, sticky="ew", pady=4)
    ttk.Label(enroll_box, text="Pico-FIDO PIN").grid(row=4, column=0, sticky="w", pady=4)
    ttk.Entry(enroll_box, textvariable=enroll_pin_var, show="*", width=58).grid(row=4, column=1, columnspan=2, sticky="ew", pady=4)
    enroll_actions = ttk.Frame(enroll_box)
    enroll_actions.grid(row=5, column=0, columnspan=3, sticky="w", pady=(10, 0))
    ttk.Button(enroll_actions, text="Enroll vault", command=enroll).pack(side="left")
    ttk.Button(enroll_actions, text="Unenroll vault", command=unenroll).pack(side="left", padx=(8, 0))

    buttons = ttk.Frame(form)
    buttons.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(8, 0))
    ttk.Button(buttons, text="Open vault folder", command=_open_enrollment_directory).pack(side="left")
    ttk.Label(form, textvariable=status_var, wraplength=650).grid(row=3, column=0, columnspan=2, sticky="w", pady=12)
    root.mainloop()

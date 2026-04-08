import base64
import getpass
import json
import os
import sys
from typing import Any, Dict, List, Optional

import serial
from cryptography.fernet import Fernet, InvalidToken
from serial.tools import list_ports


VAULT_FILE = "vault.enc"
BAUD_RATE = 115200
SERIAL_TIMEOUT_SEC = 3


def prompt_masked(prompt: str, digits_only: bool = False, max_len: Optional[int] = None) -> str:
    """Read secret from terminal while echoing '*' for each typed char."""
    try:
        import msvcrt  # Windows-only
    except ImportError:
        # Fallback for non-Windows terminals.
        return getpass.getpass(prompt)

    sys.stdout.write(prompt)
    sys.stdout.flush()

    chars: List[str] = []
    while True:
        ch = msvcrt.getwch()

        if ch in ("\r", "\n"):
            sys.stdout.write("\n")
            sys.stdout.flush()
            break

        if ch == "\003":
            raise KeyboardInterrupt

        if ch in ("\b", "\x7f"):
            if chars:
                chars.pop()
                sys.stdout.write("\b \b")
                sys.stdout.flush()
            continue

        if max_len is not None and len(chars) >= max_len:
            continue

        if digits_only and not ch.isdigit():
            continue

        if ch.isprintable():
            chars.append(ch)
            sys.stdout.write("*")
            sys.stdout.flush()

    return "".join(chars)


def prompt_pin_masked(prompt: str) -> str:
    return prompt_masked(prompt, digits_only=True, max_len=4)


def score_arduino_likelihood(port: Any) -> int:
    text_parts = [
        str(getattr(port, "device", "")),
        str(getattr(port, "description", "")),
        str(getattr(port, "manufacturer", "")),
        str(getattr(port, "product", "")),
        str(getattr(port, "hwid", "")),
    ]
    haystack = " ".join(text_parts).lower()

    strong_hits = ("arduino", "cp210", "ch340", "usb serial", "wch", "ftdi")
    score = 0
    for token in strong_hits:
        if token in haystack:
            score += 2
    if "vid:pid" in haystack:
        score += 1
    return score


def choose_port() -> str:
    ports = list(list_ports.comports())
    if not ports:
        raise RuntimeError("No serial devices detected. Plug in the Arduino and try again.")

    if len(ports) == 1:
        only = ports[0]
        score = score_arduino_likelihood(only)
        tag = " [LIKELY ARDUINO]" if score > 0 else ""
        print(f"Using detected port: {only.device} ({only.description}){tag}")
        return only.device

    scored_ports = sorted(
        [(port, score_arduino_likelihood(port)) for port in ports],
        key=lambda item: item[1],
        reverse=True,
    )
    best_device = scored_ports[0][0].device if scored_ports and scored_ports[0][1] > 0 else None

    print("Detected serial ports:")
    for idx, port in enumerate(ports, start=1):
        score = score_arduino_likelihood(port)
        tags: List[str] = []
        if score > 0:
            tags.append("LIKELY ARDUINO")
        if best_device is not None and port.device == best_device:
            tags.append("BEST MATCH")
        tag_text = f" [{' | '.join(tags)}]" if tags else ""
        print(f"  [{idx}] {port.device} - {port.description}{tag_text}")

    if best_device is not None:
        print(f"Hint: {best_device} appears to be your Arduino.")

    while True:
        choice = input("Select port number or enter full COM name (e.g., COM4): ").strip()
        if choice.isdigit():
            selected = int(choice)
            if 1 <= selected <= len(ports):
                return ports[selected - 1].device
        elif choice:
            return choice
        print("Invalid selection. Try again.")


def bytes_to_hex(data: bytes) -> str:
    return data.hex().upper()


def hex_to_bytes(text: str, expected_len: int) -> bytes:
    clean = text.strip()
    decoded = bytes.fromhex(clean)
    if len(decoded) != expected_len:
        raise ValueError(f"Expected {expected_len} bytes but got {len(decoded)}.")
    return decoded


def parse_vault_file(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {"version": 1, "salt": bytes_to_hex(os.urandom(16)), "ciphertext": ""}

    with open(path, "rb") as f:
        raw = f.read()

    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("vault.enc is not valid JSON envelope format.") from exc

    if (
        not isinstance(decoded, dict)
        or decoded.get("version") != 1
        or not isinstance(decoded.get("salt"), str)
        or not isinstance(decoded.get("ciphertext"), str)
    ):
        raise RuntimeError("vault.enc envelope is invalid. Expected keys: version, salt, ciphertext.")

    # Validate salt syntax early to avoid serial command misuse.
    _ = hex_to_bytes(decoded["salt"], 16)
    return decoded


def request_derived_key_from_hardware(port: str, salt_hex: str) -> bytearray:
    pin = prompt_pin_masked("Enter 4-digit PIN: ").strip()
    if len(pin) != 4 or not pin.isdigit():
        raise ValueError("PIN must be exactly 4 digits.")

    ser = serial.Serial(port=port, baudrate=BAUD_RATE, timeout=SERIAL_TIMEOUT_SEC)
    try:
        # Give Arduino time to reset after opening the serial port.
        ser.reset_input_buffer()
        ser.reset_output_buffer()

        # Read/ignore initial startup lines like READY.
        for _ in range(3):
            maybe_line = ser.readline()
            if not maybe_line:
                break

        ser.write(f"AUTH {pin}\n".encode("ascii"))
        ser.flush()

        response = ser.readline().decode("ascii", errors="ignore").strip()
        if response != "GRANTED":
            if not response:
                raise RuntimeError("No response from hardware key.")
            raise PermissionError(f"Hardware denied access: {response}")

        ser.write(f"DERIVE {salt_hex}\n".encode("ascii"))
        ser.flush()

        derive_line = ser.readline().decode("ascii", errors="ignore").strip()
        if not derive_line.startswith("DERIVED "):
            if not derive_line:
                raise RuntimeError("No derive response from hardware key.")
            raise RuntimeError(f"Unexpected derive response: {derive_line}")

        derived_hex = derive_line.split(" ", 1)[1].strip()
        raw_key = bytearray(hex_to_bytes(derived_hex, 32))

        # Immediately clear serial buffers to reduce key exposure in transit buffers.
        ser.reset_input_buffer()
        ser.reset_output_buffer()
        return raw_key
    finally:
        ser.close()


def is_valid_pin(pin: str) -> bool:
    return len(pin) == 4 and pin.isdigit()


def change_hardware_pin(port: str) -> bool:
    current_pin = prompt_pin_masked("Current 4-digit PIN: ").strip()
    if not is_valid_pin(current_pin):
        print("Current PIN must be exactly 4 digits.")
        return False

    new_pin = prompt_pin_masked("New 4-digit PIN: ").strip()
    if not is_valid_pin(new_pin):
        print("New PIN must be exactly 4 digits.")
        return False

    confirm_pin = prompt_pin_masked("Confirm new PIN: ").strip()
    if new_pin != confirm_pin:
        print("New PINs do not match.")
        return False

    ser = serial.Serial(port=port, baudrate=BAUD_RATE, timeout=SERIAL_TIMEOUT_SEC)
    try:
        ser.reset_input_buffer()
        ser.reset_output_buffer()

        # Clear boot/banner lines after possible board reset on open.
        for _ in range(3):
            maybe_line = ser.readline()
            if not maybe_line:
                break

        ser.write(f"CHANGEPIN {current_pin} {new_pin}\n".encode("ascii"))
        ser.flush()
        response = ser.readline().decode("ascii", errors="ignore").strip()

        ser.reset_input_buffer()
        ser.reset_output_buffer()

        if response == "PIN UPDATED":
            print("Hardware PIN updated successfully.")
            return True
        if response:
            print(f"PIN change failed: {response}")
            return False
        print("PIN change failed: no response from hardware.")
        return False
    finally:
        ser.close()


def build_fernet(device_key: bytearray) -> Fernet:
    # Fernet expects a urlsafe-base64 key format; this conversion remains in RAM only.
    fernet_key = base64.urlsafe_b64encode(bytes(device_key))
    return Fernet(fernet_key)


def load_or_create_vault(
    fernet: Fernet, vault_path: str, vault_envelope: Dict[str, Any]
) -> Dict[str, List[Dict[str, str]]]:
    ciphertext = vault_envelope["ciphertext"]
    if not ciphertext:
        data = {"accounts": []}
        save_vault(fernet, vault_path, vault_envelope, data)
        return data

    try:
        plaintext = fernet.decrypt(ciphertext.encode("utf-8"))
    except InvalidToken as exc:
        raise RuntimeError("Failed to decrypt vault. Wrong PIN/key or vault is corrupted.") from exc

    try:
        obj = json.loads(plaintext.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError("Vault decrypted but JSON is invalid.") from exc

    if "accounts" not in obj or not isinstance(obj["accounts"], list):
        raise RuntimeError("Vault format invalid: expected {'accounts': [...]} structure.")
    return obj


def save_vault(
    fernet: Fernet, path: str, envelope: Dict[str, Any], data: Dict[str, List[Dict[str, str]]]
) -> None:
    plaintext = json.dumps(data, indent=2).encode("utf-8")
    encrypted = fernet.encrypt(plaintext)
    envelope["ciphertext"] = encrypted.decode("utf-8")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(envelope, f, indent=2)
        f.write("\n")


def view_accounts(vault: Dict[str, List[Dict[str, str]]]) -> None:
    accounts = vault["accounts"]
    if not accounts:
        print("\nVault is empty.\n")
        return

    print("\nStored Accounts:")
    for idx, item in enumerate(accounts, start=1):
        print(f"[{idx}] Service: {item['service']}")
        print(f"    Username: {item['username']}")
        print(f"    Password: {item['password']}")
    print("")


def add_account(vault: Dict[str, List[Dict[str, str]]]) -> bool:
    service = input("Service: ").strip()
    username = input("Username: ").strip()
    password = prompt_masked("Password: ").strip()

    if not service or not username or not password:
        print("All fields are required.")
        return False

    vault["accounts"].append(
        {
            "service": service,
            "username": username,
            "password": password,
        }
    )
    print("Account added.")
    return True


def edit_account(vault: Dict[str, List[Dict[str, str]]]) -> bool:
    accounts = vault["accounts"]
    if not accounts:
        print("No accounts to edit.")
        return False

    view_accounts(vault)
    choice = input("Enter account number to edit: ").strip()
    if not choice.isdigit():
        print("Invalid selection.")
        return False

    idx = int(choice) - 1
    if idx < 0 or idx >= len(accounts):
        print("Selection out of range.")
        return False

    item = accounts[idx]
    print("Press Enter to keep current value.")
    new_service = input(f"Service [{item['service']}]: ").strip()
    new_username = input(f"Username [{item['username']}]: ").strip()
    new_password = prompt_masked("Password [hidden]: ").strip()

    if new_service:
        item["service"] = new_service
    if new_username:
        item["username"] = new_username
    if new_password:
        item["password"] = new_password

    print("Account updated.")
    return True


def delete_account(vault: Dict[str, List[Dict[str, str]]]) -> bool:
    accounts = vault["accounts"]
    if not accounts:
        print("No accounts to delete.")
        return False

    view_accounts(vault)
    choice = input("Enter account number to delete: ").strip()
    if not choice.isdigit():
        print("Invalid selection.")
        return False

    idx = int(choice) - 1
    if idx < 0 or idx >= len(accounts):
        print("Selection out of range.")
        return False

    removed = accounts.pop(idx)
    print(f"Deleted account for service: {removed['service']}")
    return True


def menu_loop(
    fernet: Fernet,
    port: str,
    vault_path: str,
    vault_envelope: Dict[str, Any],
    vault_data: Dict[str, List[Dict[str, str]]],
) -> None:
    while True:
        print("Password Vault Menu")
        print("[1] View all accounts")
        print("[2] Add a new account")
        print("[3] Edit an account")
        print("[4] Delete an account")
        print("[5] Change hardware PIN")
        print("[6] Safely Lock & Exit")
        choice = input("Choose an option: ").strip()

        changed = False
        if choice == "1":
            view_accounts(vault_data)
        elif choice == "2":
            changed = add_account(vault_data)
        elif choice == "3":
            changed = edit_account(vault_data)
        elif choice == "4":
            changed = delete_account(vault_data)
        elif choice == "5":
            change_hardware_pin(port)
        elif choice == "6":
            print("Vault locked. Exiting.")
            return
        else:
            print("Invalid option.")

        if changed:
            save_vault(fernet, vault_path, vault_envelope, vault_data)
            print("Vault re-encrypted and saved.\n")


def zeroize(buf: Optional[bytearray]) -> None:
    if buf is None:
        return
    for i in range(len(buf)):
        buf[i] = 0


def main() -> int:
    vault_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), VAULT_FILE)
    device_key = None
    try:
        print("=== Hardware-Secured Password Vault ===")
        port = choose_port()
        vault_envelope = parse_vault_file(vault_path)
        device_key = request_derived_key_from_hardware(port, vault_envelope["salt"])

        fernet = build_fernet(device_key)
        vault = load_or_create_vault(fernet, vault_path, vault_envelope)
        menu_loop(fernet, port, vault_path, vault_envelope, vault)
        return 0
    except (RuntimeError, PermissionError, ValueError, serial.SerialException) as exc:
        print(f"Error: {exc}")
        return 1
    finally:
        zeroize(device_key)


if __name__ == "__main__":
    sys.exit(main())

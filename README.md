# Hardware-Secured Vault (Python + Arduino)

This project uses:

- `vault_cli.py` (Python): CLI that manages encrypted account data.
- `hardware_key/hardware_key.ino` (Arduino): hardware key firmware that verifies PIN and derives an encryption key.
- `vault.enc`: encrypted vault data file generated/updated by the Python CLI.

## Requirements

### Arduino side

- Arduino board connected over USB.
- `hardware_key/hardware_key.ino` flashed to the board.

Before flashing, update these in `hardware_key/hardware_key.ino`:

- `DEFAULT_PIN` (4 digits)
- `DEFAULT_KEY` (random 32-byte key)

> Important: generate your own random key before using this project.

### Python side

- Python 3.10+ recommended
- Packages:
  - `pyserial`
  - `cryptography`

Install:

```bash
pip install pyserial cryptography
```

## Flash the Arduino sketch

Use Arduino IDE, or `arduino-cli`:

```bash
arduino-cli compile --fqbn arduino:avr:uno hardware_key
arduino-cli upload -p COM3 --fqbn arduino:avr:uno hardware_key
```

Adjust:

- board FQBN (`arduino:avr:uno` is an example)
- serial port (`COM3` is an example)

## Run the vault CLI

From the `Simulator` folder:

```bash
python vault_cli.py
```

What happens:

1. The script detects/selects a serial port.
2. You enter a 4-digit PIN.
3. Python asks the Arduino to derive a key from the vault salt.
4. `vault.enc` is decrypted (or created if missing).
5. You manage account entries from the menu.

## Vault file format

`vault.enc` is a JSON envelope:

- `version`
- `salt` (hex)
- `ciphertext` (Fernet-encrypted JSON payload)


## Security notes

- Keep your custom `DEFAULT_KEY` private.
- Keep your PIN private.
- If either is exposed, treat vault data as compromised.
- For stronger security, consider changing defaults, rotating keys, and storing fewer plaintext secrets.

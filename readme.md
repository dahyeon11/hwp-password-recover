# HWP Password Recover

A Python 3 tool for recovering passwords from HWP (Hancom Office) files. This tool can unlock HWP files with known passwords or attempt to crack them using brute-force.

> **Note**: This tool was originally developed for educational purposes and used in Codegate 2018 prequal challenge.

## Features

- **Unlock**: Decrypt HWP files with a known password
- **Crack**: Brute-force password recovery with customizable patterns
- **CLI Interface**: Easy-to-use command-line interface
- **Python 3**: Updated from Python 2 to Python 3 with modern syntax

## Installation

1. Clone this repository:
```bash
git clone https://github.com/yourusername/hwp-password-recover.git
cd hwp-password-recover
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Unlock HWP File with Known Password

```bash
python3 hwp_cli.py unlock <file.hwp> -p <password>
```

**Example:**
```bash
python3 hwp_cli.py unlock document.hwp -p mypassword
```

### Brute-force Password Cracking

```bash
python3 hwp_cli.py crack <file.hwp> -P <pattern> [options]
```

**Options:**
- `-P, --pattern`: Password pattern with `{}` placeholders (required)
- `-c, --charset`: Character set to use (default: lowercase letters a-z)
- `-m, --max-attempts`: Maximum number of attempts
- `-u, --unlock`: Automatically unlock file when password is found

**Examples:**

1. Crack with pattern "abc{}{}" using default charset (a-z):
```bash
python3 hwp_cli.py crack document.hwp -P "abc{}{}"
```

2. Crack with pattern "{}{}{}{}" using custom charset:
```bash
python3 hwp_cli.py crack document.hwp -P "{}{}{}{}" -c "0123456789"
```

3. Crack and automatically unlock when found:
```bash
python3 hwp_cli.py crack document.hwp -P "pass{}{}" -c "123" -u
```

4. Limit attempts to 10000:
```bash
python3 hwp_cli.py crack document.hwp -P "{}{}{}" -m 10000
```

### Get Help

```bash
python3 hwp_cli.py -h
python3 hwp_cli.py unlock -h
python3 hwp_cli.py crack -h
```

## How It Works

This tool implements the HWP file encryption/decryption algorithm:

1. **Key Generation** (`password.py`): Converts password to a 16-byte AES key using custom bit-shifting and SHA1 hashing
2. **Encryption/Decryption** (`utils.py`): Uses AES ECB mode with a custom CFB-like stream cipher
3. **HWP Handling** (`hwp.py`): Reads and writes OLE compound document format, decrypts DocInfo and BodyText streams

## Requirements

- Python 3.6+
- pycryptodome
- olefile

## Security Warning

This tool is for **educational and authorized security research purposes only**. Use it responsibly:
- Only on files you own or have explicit permission to test
- For CTF challenges and security competitions
- For password recovery of your own files

Unauthorized access to password-protected files may be illegal in your jurisdiction.

## License

Educational and research purposes only.

## Credits

- Original implementation based on HWP encryption algorithm
- Used in Codegate 2018 prequal challenge

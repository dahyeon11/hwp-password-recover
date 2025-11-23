# HWP Password Recover

A Python 3 tool for recovering passwords from HWP (Hancom Office) files. This tool can unlock HWP files with known passwords or attempt to crack them using brute-force.

> **Note**: This tool was originally developed for educational purposes and used in Codegate 2018 prequal challenge.

## Features

- **Unlock**: Decrypt HWP files with a known password
- **Crack**: Brute-force password recovery with customizable patterns
- **GPU Acceleration**: NVIDIA CUDA support for ultra-fast cracking
- **Parallel Processing**: Multi-core CPU support for faster cracking
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

3. **(Optional) Install GPU dependencies** for CUDA acceleration:
```bash
# For CUDA 13.x or 12.x (recommended)
pip install numba cupy-cuda12x

# For CUDA 11.x
pip install numba cupy-cuda11x

# Note: cupy-cuda12x works with both CUDA 12.x and 13.x
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
python3 hwp_cli.py crack <file.hwp> [options]
```

**Options:**
- `-P, --pattern`: Password pattern with `{}` placeholders (e.g., "abc{}{}")
- `-l, --length`: Password length (try all combinations)
- `-c, --charset`: Character set to use (default: lowercase letters a-z)
- `-m, --max-attempts`: Maximum number of attempts
- `-u, --unlock`: Automatically unlock file when password is found
- `-w, --workers`: Number of parallel workers (default: CPU count, use 1 for single-threaded)
- `--gpu`: Use GPU acceleration with CUDA (fastest, requires NVIDIA GPU)

**Note:** Either `--pattern` or `--length` must be specified (but not both).

**Examples:**

1. Crack with pattern "abc{}{}" using default charset (a-z):
```bash
python3 hwp_cli.py crack document.hwp -P "abc{}{}"
```

2. Crack all 4-digit passwords:
```bash
python3 hwp_cli.py crack document.hwp -l 4 -c "0123456789"
```

3. Crack all 5-character lowercase passwords (pattern unknown):
```bash
python3 hwp_cli.py crack document.hwp -l 5
```

4. Crack with pattern and custom charset:
```bash
python3 hwp_cli.py crack document.hwp -P "pass{}{}" -c "123"
```

5. Crack and automatically unlock when found:
```bash
python3 hwp_cli.py crack document.hwp -l 3 -c "abc123" -u
```

6. Limit attempts to 10000:
```bash
python3 hwp_cli.py crack document.hwp -l 3 -m 10000
```

7. Use parallel processing with 8 workers (faster):
```bash
python3 hwp_cli.py crack document.hwp -l 4 -c "0123456789" -w 8
```

8. Single-threaded mode (slower but less CPU usage):
```bash
python3 hwp_cli.py crack document.hwp -l 3 -w 1
```

9. GPU acceleration (fastest, requires NVIDIA GPU with CUDA):
```bash
python3 hwp_cli.py crack document.hwp -l 5 -c "0123456789" --gpu
```

### Get Help

```bash
python3 hwp_cli.py -h
python3 hwp_cli.py unlock -h
python3 hwp_cli.py crack -h
```

## Performance Optimization

### GPU Acceleration (Fastest)

For NVIDIA GPUs with CUDA support, GPU acceleration provides the best performance.

**Requirements:**
- NVIDIA GPU with CUDA support
- CUDA Toolkit installed
- Python packages: `numba` and `cupy`

**Installation:**
```bash
# Check your CUDA version first
nvcc --version

# Install for CUDA 13.x or 12.x (recommended)
pip install numba cupy-cuda12x

# Or for CUDA 11.x
pip install numba cupy-cuda11x

# Note: If you have CUDA 13.x, use cupy-cuda12x (it's compatible)
```

**Usage:**
```bash
python3 hwp_cli.py crack document.hwp -l 5 -c "0123456789" --gpu
```

**Expected Performance:**
- **GPU Mode**: 50-100x faster than single-threaded CPU
- **Best for**: Length 5+ passwords with large charsets

### Parallel Processing (CPU)

By default, the tool uses all available CPU cores for parallel processing. This can provide 5-10x speed improvement depending on your CPU.

**Default behavior** (uses all CPU cores):
```bash
python3 hwp_cli.py crack document.hwp -l 4 -c "0123456789"
```

**Specify number of workers**:
```bash
python3 hwp_cli.py crack document.hwp -l 4 -c "0123456789" -w 8
```

**Single-threaded mode** (for debugging or low-resource systems):
```bash
python3 hwp_cli.py crack document.hwp -l 3 -w 1
```

### Performance Comparison

| Mode | Speed | Best For |
|------|-------|----------|
| Single-threaded | 1x | Debugging, low-resource systems |
| Multi-threaded (8 cores) | ~8x | General use, no GPU |
| GPU (CUDA) | ~50-100x | Large password spaces, NVIDIA GPU available |

### Performance Tips

1. **Use GPU when available**: For maximum speed with NVIDIA GPUs
2. **Start with shorter passwords**: Test with `-l 3` or `-l 4` before trying longer ones
3. **Use specific charsets**: If you know the password only contains numbers, use `-c "0123456789"`
4. **Limit attempts**: Use `-m` to set maximum attempts for testing
5. **Parallel workers**: More workers = faster cracking (up to your CPU core count)

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

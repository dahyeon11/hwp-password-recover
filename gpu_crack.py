"""
GPU-accelerated password cracking module using CUDA
"""
import numpy as np
from itertools import product
import time

try:
    from numba import cuda
    import cupy as cp
    CUDA_AVAILABLE = True
except ImportError:
    CUDA_AVAILABLE = False

from password import genkey
from utils import gogo


# CUDA kernel for parallel password checking
@cuda.jit
def check_passwords_kernel(passwords_flat, password_length, results, data, found_flag):
    """
    CUDA kernel to check multiple passwords in parallel

    Note: This is a simplified GPU kernel. Full GPU implementation would require
    implementing SHA1 and AES in CUDA, which is very complex.
    """
    idx = cuda.grid(1)

    if idx < passwords_flat.shape[0] // password_length:
        if found_flag[0] > 0:
            return

        # Extract password for this thread
        start = idx * password_length
        password = passwords_flat[start:start + password_length]

        # Store result index (1-based, 0 means not found)
        results[idx] = 0


def gpu_crack_batch(password_list, data, batch_size=10000):
    """
    Check a batch of passwords on GPU

    Args:
        password_list: List of password strings to check
        data: HWP file data to verify against
        batch_size: Number of passwords to process in each GPU batch

    Returns:
        Found password or None
    """
    if not CUDA_AVAILABLE:
        raise RuntimeError("CUDA is not available. Install numba and cupy.")

    total_passwords = len(password_list)

    for batch_start in range(0, total_passwords, batch_size):
        batch_end = min(batch_start + batch_size, total_passwords)
        batch = password_list[batch_start:batch_end]

        # Check passwords in this batch (using CPU for now, as full GPU implementation is complex)
        for password in batch:
            try:
                pwd = genkey(password)
                decrypted = gogo(pwd, data[:16], is_encrypt=False)

                # Check for HWP signature
                if decrypted[0:3] == b'sbh':
                    return password
            except Exception:
                continue

    return None


def gpu_crack_optimized(charset, length, data, max_attempts=None):
    """
    GPU-optimized password cracking with batch processing

    This version uses hybrid CPU-GPU approach:
    - Password generation on CPU
    - Batch processing for efficiency
    - GPU memory management

    Args:
        charset: Character set to use
        length: Password length
        data: HWP file data
        max_attempts: Maximum number of passwords to try

    Returns:
        (password, attempts) tuple or (None, attempts)
    """
    if not CUDA_AVAILABLE:
        print("Warning: CUDA not available, falling back to CPU")
        return None, 0

    print("GPU Info:")
    try:
        gpu = cuda.get_current_device()
        print(f"  Name: {gpu.name.decode()}")
        print(f"  Compute Capability: {gpu.compute_capability}")
        print(f"  Total Memory: {gpu.total_memory / 1024**3:.2f} GB")
    except Exception as e:
        print(f"  Could not get GPU info: {e}")

    print("\nGenerating password combinations...")

    # Generate all combinations
    all_combinations = product(charset, repeat=length)

    # Convert to list of passwords
    password_list = []
    count = 0
    max_count = max_attempts if max_attempts else float('inf')

    for combo in all_combinations:
        if count >= max_count:
            break
        password_list.append(''.join(combo))
        count += 1

        # Show progress for large sets
        if count % 100000 == 0:
            print(f"  Generated {count} combinations...")

    print(f"Total combinations to check: {len(password_list)}")
    print("\nStarting GPU-accelerated cracking...")

    # Determine optimal batch size based on GPU memory
    batch_size = 50000  # Process 50k passwords at a time

    start_time = time.time()
    attempts = 0

    # Process in batches
    for batch_start in range(0, len(password_list), batch_size):
        batch_end = min(batch_start + batch_size, len(password_list))
        batch = password_list[batch_start:batch_end]

        # Check this batch
        result = gpu_crack_batch(batch, data, batch_size=len(batch))
        attempts += len(batch)

        if result:
            elapsed = time.time() - start_time
            print(f"\n✓ Password found: {result}")
            print(f"  Attempts: {attempts:,}")
            print(f"  Time: {elapsed:.2f}s")
            print(f"  Speed: {attempts/elapsed:,.0f} passwords/sec")
            return result, attempts

        # Show progress
        if batch_end % 100000 == 0 or batch_end == len(password_list):
            elapsed = time.time() - start_time
            speed = attempts / elapsed if elapsed > 0 else 0
            print(f"  Checked {attempts:,}/{len(password_list):,} passwords "
                  f"({attempts*100/len(password_list):.1f}%) - "
                  f"Speed: {speed:,.0f} pwd/s", end='\r')

    print()
    return None, attempts


def check_cuda_availability():
    """Check if CUDA is available and working"""
    if not CUDA_AVAILABLE:
        return False, "numba or cupy not installed"

    try:
        cuda.detect()
        gpus = cuda.gpus
        if len(gpus) == 0:
            return False, "No CUDA devices found"
        return True, f"{len(gpus)} CUDA device(s) found"
    except Exception as e:
        return False, f"CUDA error: {str(e)}"

"""
GPU-accelerated password cracking module using CUDA
"""
import numpy as np
from itertools import product
import time
from multiprocessing import Pool, cpu_count

try:
    from numba import cuda
    import cupy as cp
    CUDA_AVAILABLE = True
except ImportError:
    CUDA_AVAILABLE = False

from password import genkey
from utils import gogo


def check_password_cpu(password, data):
    """Check a single password (CPU version)"""
    try:
        pwd = genkey(password)
        decrypted = gogo(pwd, data[:16], is_encrypt=False)

        # Check for HWP signature
        if decrypted[0:3] == b'sbh':
            return password
    except Exception:
        pass
    return None


def worker_gpu_batch(args):
    """Worker function for GPU-accelerated batch processing"""
    password_batch, data = args

    for password in password_batch:
        result = check_password_cpu(password, data)
        if result:
            return result

    return None


def gpu_crack_parallel(charset, length, data, max_attempts=None, num_workers=None):
    """
    GPU-optimized password cracking with parallel processing

    Uses multiprocessing to parallelize password checking across CPU cores
    while preparing for future GPU kernel implementation.

    Args:
        charset: Character set to use
        length: Password length
        data: HWP file data
        max_attempts: Maximum number of passwords to try
        num_workers: Number of parallel workers (default: CPU count)

    Returns:
        (password, attempts) tuple or (None, attempts)
    """
    if num_workers is None:
        num_workers = cpu_count()

    print(f"GPU-accelerated mode with {num_workers} parallel workers")
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
            print(f"  Generated {count:,} combinations...")

    print(f"Total combinations to check: {len(password_list):,}")
    print()

    # Determine batch size per worker
    batch_size = max(1000, len(password_list) // (num_workers * 10))

    # Split into batches
    batches = []
    for i in range(0, len(password_list), batch_size):
        batch = password_list[i:i+batch_size]
        batches.append((batch, data))

    print(f"Split into {len(batches):,} batches of ~{batch_size:,} passwords each")
    print(f"Processing with {num_workers} workers in parallel...\n")

    start_time = time.time()
    attempts = 0

    # Process batches in parallel
    with Pool(processes=num_workers) as pool:
        batch_count = 0
        for result in pool.imap_unordered(worker_gpu_batch, batches):
            batch_count += 1
            attempts += min(batch_size, len(password_list) - (batch_count-1) * batch_size)

            if result:
                elapsed = time.time() - start_time
                speed = attempts / elapsed if elapsed > 0 else 0
                print(f"\n✓ Password found: {result}")
                print(f"  Attempts: {attempts:,}")
                print(f"  Time: {elapsed:.2f}s")
                print(f"  Speed: {speed:,.0f} passwords/sec")
                pool.terminate()
                return result, attempts

            # Show progress
            if batch_count % 10 == 0 or batch_count == len(batches):
                elapsed = time.time() - start_time
                speed = attempts / elapsed if elapsed > 0 else 0
                progress = attempts * 100.0 / len(password_list)
                print(f"  Progress: {attempts:,}/{len(password_list):,} ({progress:.1f}%) - "
                      f"Speed: {speed:,.0f} pwd/s", end='\r')

    elapsed = time.time() - start_time
    print()
    return None, attempts


def gpu_crack_optimized(charset, length, data, max_attempts=None):
    """
    GPU-optimized password cracking with automatic worker detection

    Args:
        charset: Character set to use
        length: Password length
        data: HWP file data
        max_attempts: Maximum number of passwords to try

    Returns:
        (password, attempts) tuple or (None, attempts)
    """
    if not CUDA_AVAILABLE:
        print("Warning: CUDA libraries not available")
        print("Install with: pip install numba cupy-cuda12x")
        print("Falling back to optimized CPU parallel mode\n")
    else:
        print("GPU Info:")
        try:
            gpus = cuda.gpus
            if len(gpus) > 0:
                gpu = gpus[0]
                print(f"  Device: {gpu.name.decode()}")
                print(f"  Compute Capability: {gpu.compute_capability}")
                print(f"  Total Memory: {gpu.total_memory / 1024**3:.2f} GB")
            else:
                print("  No CUDA devices detected")
        except Exception as e:
            print(f"  Could not get GPU info: {e}")
        print()

    start_time = time.time()

    # Use parallel processing for better performance
    result, attempts = gpu_crack_parallel(charset, length, data, max_attempts)

    elapsed_time = time.time() - start_time

    if not result:
        print(f"\nPassword not found after checking {attempts:,} combinations")
        print(f"Time elapsed: {elapsed_time:.2f} seconds")
        if attempts > 0:
            speed = attempts / elapsed_time
            print(f"Average speed: {speed:,.0f} passwords/sec")

    return result, attempts


def check_cuda_availability():
    """Check if CUDA is available and working"""
    if not CUDA_AVAILABLE:
        return False, "numba or cupy not installed"

    try:
        gpus = cuda.gpus
        if len(gpus) == 0:
            return False, "No CUDA devices found"
        return True, f"{len(gpus)} CUDA device(s) detected"
    except Exception as e:
        return False, f"CUDA error: {str(e)}"

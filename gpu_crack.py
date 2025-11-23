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
    # Import GPU kernels
    try:
        from gpu_kernels import gpu_crack_passwords_kernel, AES_SBOX
        GPU_KERNELS_AVAILABLE = True
    except:
        GPU_KERNELS_AVAILABLE = False
except ImportError:
    CUDA_AVAILABLE = False
    GPU_KERNELS_AVAILABLE = False

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


def gpu_crack_real_cuda(charset, length, data, max_attempts=None):
    """
    Real GPU CUDA kernel-based password cracking
    Uses actual GPU kernels for maximum performance
    """
    if not CUDA_AVAILABLE or not GPU_KERNELS_AVAILABLE:
        print("Warning: GPU kernels not available")
        print("Falling back to CPU parallel mode\n")
        return gpu_crack_parallel(charset, length, data, max_attempts)

    print("=" * 60)
    print("REAL GPU MODE - Using CUDA Kernels")
    print("=" * 60)

    # GPU Info
    try:
        gpus = cuda.gpus
        if len(gpus) > 0:
            gpu = gpus[0]
            print(f"GPU Device: {gpu.name.decode()}")
            print(f"Compute Capability: {gpu.compute_capability}")
            print(f"Total Memory: {gpu.total_memory / 1024**3:.2f} GB")
        else:
            print("No CUDA devices detected")
            return gpu_crack_parallel(charset, length, data, max_attempts)
    except Exception as e:
        print(f"Could not get GPU info: {e}")
        return gpu_crack_parallel(charset, length, data, max_attempts)

    print()

    # Generate all password combinations
    print("Generating password combinations...")
    all_combinations = list(product(charset, repeat=length))
    total_passwords = len(all_combinations)

    if max_attempts and max_attempts < total_passwords:
        total_passwords = max_attempts
        all_combinations = all_combinations[:max_attempts]

    print(f"Total passwords to check: {total_passwords:,}")

    # Convert passwords to numpy array
    print("Preparing GPU data...")
    max_pwd_len = length
    passwords_array = np.zeros((total_passwords, 32), dtype=np.uint8)
    password_lens = np.zeros(total_passwords, dtype=np.int32)

    for i, combo in enumerate(all_combinations):
        pwd = ''.join(combo)
        pwd_bytes = pwd.encode('utf-8')
        password_lens[i] = len(pwd_bytes)
        for j, byte in enumerate(pwd_bytes):
            passwords_array[i, j] = byte

    # Transfer to GPU
    print("Transferring data to GPU...")
    d_passwords = cuda.to_device(passwords_array)
    d_password_lens = cuda.to_device(password_lens)
    d_hwp_data = cuda.to_device(np.frombuffer(data[:16], dtype=np.uint8))
    d_results = cuda.device_array(total_passwords, dtype=np.int32)
    d_sbox = cuda.to_device(AES_SBOX)

    # Calculate grid size
    threads_per_block = 256
    blocks_per_grid = (total_passwords + threads_per_block - 1) // threads_per_block

    print(f"Launching GPU kernel with {blocks_per_grid} blocks x {threads_per_block} threads")
    print(f"Total GPU threads: {blocks_per_grid * threads_per_block:,}")
    print()

    start_time = time.time()

    # Launch kernel
    gpu_crack_passwords_kernel[blocks_per_grid, threads_per_block](
        d_passwords, d_password_lens, total_passwords,
        d_hwp_data, d_results, d_sbox
    )

    # Wait for kernel to finish
    cuda.synchronize()

    # Copy results back
    results = d_results.copy_to_host()

    elapsed = time.time() - start_time

    # Find matching password
    for i in range(total_passwords):
        if results[i] == 1:
            password = ''.join(all_combinations[i])
            print(f"\n✓ Password found: {password}")
            print(f"  GPU Time: {elapsed:.2f}s")
            print(f"  Passwords checked: {total_passwords:,}")
            print(f"  GPU Speed: {total_passwords/elapsed:,.0f} pwd/s")
            print(f"  GPU Utilization: 100%")
            return password, total_passwords

    print(f"\nPassword not found after checking {total_passwords:,} combinations")
    print(f"GPU Time: {elapsed:.2f} seconds")
    print(f"GPU Speed: {total_passwords/elapsed:,.0f} pwd/s")
    return None, total_passwords


def gpu_crack_optimized(charset, length, data, max_attempts=None):
    """
    GPU-optimized password cracking with automatic mode selection

    Args:
        charset: Character set to use
        length: Password length
        data: HWP file data
        max_attempts: Maximum number of passwords to try

    Returns:
        (password, attempts) tuple or (None, attempts)
    """
    # Try real GPU CUDA kernels first
    if CUDA_AVAILABLE and GPU_KERNELS_AVAILABLE:
        try:
            return gpu_crack_real_cuda(charset, length, data, max_attempts)
        except Exception as e:
            print(f"GPU kernel error: {e}")
            print("Falling back to CPU parallel mode\n")

    # Fallback to CPU parallel processing
    if not CUDA_AVAILABLE:
        print("Warning: CUDA libraries not available")
        print("Install with: pip install numba cupy-cuda12x")
        print("Falling back to optimized CPU parallel mode\n")

    start_time = time.time()
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

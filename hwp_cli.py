#!/usr/bin/env python3
"""
HWP Password Recovery CLI Tool
"""
import argparse
import sys
import os
import olefile
from string import ascii_lowercase
from itertools import product, islice
from multiprocessing import Pool, cpu_count, Manager
import time

from utils import gogo
from password import genkey
from hwp import unlock_hwp


def worker_crack(args_tuple):
    """Worker function for parallel password cracking"""
    combinations, data, pattern, found_flag = args_tuple

    for combination in combinations:
        # Check if another worker already found the password
        if found_flag.value:
            return None

        # Build password based on pattern or length
        if pattern:
            password = pattern.format(*combination)
        else:
            password = ''.join(combination)

        try:
            pwd = genkey(password)
            decrypted = gogo(pwd, data[:16], is_encrypt=False)

            # Check for HWP signature
            if decrypted[0:3] == b'sbh':
                found_flag.value = True
                return password
        except Exception:
            continue

    return None


def unlock_command(args):
    """Unlock HWP file with given password"""
    if not os.path.exists(args.file):
        print(f"Error: File '{args.file}' not found")
        return 1

    try:
        print(f"Unlocking '{args.file}' with password...")
        unlock_hwp(args.file, args.password)
        print(f"Success! File '{args.file}' has been unlocked")
        return 0
    except Exception as e:
        print(f"Error: Failed to unlock file - {e}")
        return 1


def crack_command(args):
    """Brute-force crack HWP file password"""
    if not os.path.exists(args.file):
        print(f"Error: File '{args.file}' not found")
        return 1

    # Validate arguments
    if not args.pattern and not args.length:
        print("Error: Either --pattern or --length must be specified")
        return 1

    if args.pattern and args.length:
        print("Error: Cannot use both --pattern and --length together")
        return 1

    try:
        ole = olefile.OleFileIO(args.file)
        stream = ole.openstream("BodyText/Section0")
        data = stream.read()
    except Exception as e:
        print(f"Error: Failed to read HWP file - {e}")
        return 1

    # Parse charset
    charset = args.charset if args.charset else ascii_lowercase

    # Determine pattern or length
    if args.pattern:
        pattern = args.pattern
        num_placeholders = pattern.count('{}')

        if num_placeholders == 0:
            print("Error: Pattern must contain at least one '{}' placeholder")
            return 1

        print(f"Starting brute-force attack on '{args.file}'")
        print(f"Mode: Pattern-based")
        print(f"Pattern: {pattern}")
    else:
        # Length-based mode
        num_placeholders = args.length
        pattern = None

        print(f"Starting brute-force attack on '{args.file}'")
        print(f"Mode: Length-based (all combinations)")
        print(f"Password length: {args.length}")

    total_combinations = len(charset)**num_placeholders
    print(f"Character set: {charset}")
    print(f"Number of positions: {num_placeholders}")
    print(f"Total combinations: {total_combinations}")

    # Determine number of workers
    num_workers = args.workers if args.workers else cpu_count()

    if num_workers > 1:
        print(f"Workers: {num_workers} (parallel mode)")
    else:
        print(f"Workers: 1 (single-threaded mode)")

    print()

    start_time = time.time()
    max_attempts = args.max_attempts if args.max_attempts else total_combinations

    # Single-threaded mode
    if num_workers == 1:
        return _crack_single_threaded(
            data, pattern, charset, num_placeholders,
            max_attempts, args.file, args.unlock
        )

    # Multi-threaded mode
    return _crack_parallel(
        data, pattern, charset, num_placeholders,
        max_attempts, num_workers, args.file, args.unlock, start_time
    )


def _crack_single_threaded(data, pattern, charset, num_placeholders,
                           max_attempts, filename, auto_unlock):
    """Single-threaded cracking"""
    attempts = 0

    for combination in product(charset, repeat=num_placeholders):
        if attempts >= max_attempts:
            print(f"\nReached maximum attempts ({max_attempts})")
            return 1

        # Build password based on pattern or length
        if pattern:
            password = pattern.format(*combination)
        else:
            password = ''.join(combination)

        attempts += 1

        if attempts % 1000 == 0:
            print(f"Tried {attempts} passwords... Current: {password}", end='\r')

        try:
            pwd = genkey(password)
            decrypted = gogo(pwd, data[:16], is_encrypt=False)

            # Check for HWP signature
            if decrypted[0:3] == b'sbh':
                print(f"\n\nPassword found: {password}")
                print(f"Attempts: {attempts}")

                if auto_unlock:
                    print(f"\nUnlocking file...")
                    unlock_hwp(filename, password)
                    print(f"Success! File has been unlocked")

                return 0
        except Exception:
            continue

    print(f"\n\nPassword not found after {attempts} attempts")
    return 1


def _crack_parallel(data, pattern, charset, num_placeholders,
                    max_attempts, num_workers, filename, auto_unlock, start_time):
    """Parallel cracking using multiprocessing"""

    # Generate all combinations
    all_combinations = list(product(charset, repeat=num_placeholders))
    total = min(len(all_combinations), max_attempts)

    # Split work among workers
    chunk_size = total // num_workers
    if chunk_size == 0:
        chunk_size = 1
        num_workers = total

    # Create shared flag for found password
    manager = Manager()
    found_flag = manager.Value('i', False)

    # Prepare work chunks
    work_chunks = []
    for i in range(num_workers):
        start_idx = i * chunk_size
        if i == num_workers - 1:
            end_idx = total
        else:
            end_idx = (i + 1) * chunk_size

        chunk = all_combinations[start_idx:end_idx]
        work_chunks.append((chunk, data, pattern, found_flag))

    print(f"Splitting {total} combinations into {num_workers} chunks of ~{chunk_size} each")
    print()

    # Start parallel processing
    result_password = None
    with Pool(processes=num_workers) as pool:
        results = pool.map(worker_crack, work_chunks)

        # Find the password from results
        for result in results:
            if result is not None:
                result_password = result
                break

    elapsed_time = time.time() - start_time

    if result_password:
        print(f"\n\nPassword found: {result_password}")
        print(f"Time elapsed: {elapsed_time:.2f} seconds")

        if auto_unlock:
            print(f"\nUnlocking file...")
            unlock_hwp(filename, result_password)
            print(f"Success! File has been unlocked")

        return 0
    else:
        print(f"\n\nPassword not found after checking {total} combinations")
        print(f"Time elapsed: {elapsed_time:.2f} seconds")
        return 1


def main():
    parser = argparse.ArgumentParser(
        description='HWP Password Recovery Tool - Unlock or crack password-protected HWP files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Unlock HWP file with known password
  %(prog)s unlock document.hwp -p mypassword

  # Brute-force crack with pattern
  %(prog)s crack document.hwp -P "abc{}{}" -c "12345"

  # Crack with length (try all 4-character combinations)
  %(prog)s crack document.hwp -l 4 -c "0123456789"

  # Crack with custom charset and auto-unlock
  %(prog)s crack document.hwp -l 5 -c "abcdefghijk" -u

  # Crack with 8 parallel workers
  %(prog)s crack document.hwp -l 4 -c "0123456789" -w 8
"""
    )

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Unlock command
    unlock_parser = subparsers.add_parser(
        'unlock',
        help='Unlock HWP file with known password'
    )
    unlock_parser.add_argument(
        'file',
        help='Path to HWP file'
    )
    unlock_parser.add_argument(
        '-p', '--password',
        required=True,
        help='Password to unlock the file'
    )
    unlock_parser.set_defaults(func=unlock_command)

    # Crack command
    crack_parser = subparsers.add_parser(
        'crack',
        help='Brute-force crack HWP file password'
    )
    crack_parser.add_argument(
        'file',
        help='Path to HWP file'
    )
    crack_parser.add_argument(
        '-P', '--pattern',
        help='Password pattern with {} placeholders (e.g., "abc{}{}")'
    )
    crack_parser.add_argument(
        '-l', '--length',
        type=int,
        help='Password length (try all combinations of this length)'
    )
    crack_parser.add_argument(
        '-c', '--charset',
        help='Character set to use for brute-force (default: lowercase letters)'
    )
    crack_parser.add_argument(
        '-m', '--max-attempts',
        type=int,
        help='Maximum number of attempts'
    )
    crack_parser.add_argument(
        '-u', '--unlock',
        action='store_true',
        help='Automatically unlock file when password is found'
    )
    crack_parser.add_argument(
        '-w', '--workers',
        type=int,
        help=f'Number of parallel workers (default: {cpu_count()}, use 1 for single-threaded)'
    )
    crack_parser.set_defaults(func=crack_command)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())

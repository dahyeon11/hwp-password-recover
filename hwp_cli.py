#!/usr/bin/env python3
"""
HWP Password Recovery CLI Tool
"""
import argparse
import sys
import os
import olefile
from string import ascii_lowercase
from itertools import product

from utils import gogo
from password import genkey
from hwp import unlock_hwp


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

    print(f"Character set: {charset}")
    print(f"Number of positions: {num_placeholders}")
    print(f"Total combinations: {len(charset)**num_placeholders}")
    print()

    attempts = 0
    max_attempts = args.max_attempts if args.max_attempts else float('inf')

    # Generate all combinations
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

                if args.unlock:
                    print(f"\nUnlocking file...")
                    unlock_hwp(args.file, password)
                    print(f"Success! File has been unlocked")

                return 0
        except Exception:
            continue

    print(f"\n\nPassword not found after {attempts} attempts")
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
    crack_parser.set_defaults(func=crack_command)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())

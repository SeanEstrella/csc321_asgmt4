import bcrypt
import logging
import time
from concurrent.futures import ThreadPoolExecutor
import argparse
import cProfile
import pstats
import io
import json
import multiprocessing
from logging.handlers import RotatingFileHandler

# Configure logging with rotation
logger = logging.getLogger()
logger.setLevel(logging.INFO)
handler = RotatingFileHandler('password_cracking.log', maxBytes=5 * 1024 * 1024, backupCount=2)
formatter = logging.Formatter('%(asctime)s:%(levelname)s:%(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)


def load_wordlist(filename):
    """Load the wordlist from a file, assuming one word per line, encoded in UTF-8."""
    wordlist = []
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as file:
            wordlist = [line.strip().encode('utf-8') for line in file if line.strip()]
    except Exception as e:
        logger.error(f"Failed to load wordlist: {e}")
    return wordlist


def check_password(entry, passwords):
    """Attempt to match any of the passwords against the provided bcrypt hash."""
    try:
        for password in passwords:
            if bcrypt.checkpw(password, entry['hash'].encode('utf-8')):
                return entry['user'], password.decode()
    except Exception as e:
        logger.error(f"Error checking password for {entry['user']}: {e}")
    return None


def crack_passwords(shadow_data, wordlist):
    """Process the password list using multiple threads with dynamic worker allocation."""
    num_workers = multiprocessing.cpu_count()
    chunk_size = len(wordlist) // num_workers
    remainder = len(wordlist) % num_workers
    with ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = []
        start_index = 0
        for entry in shadow_data:
            for _ in range(num_workers):
                end_index = start_index + chunk_size + (1 if remainder > 0 else 0)
                if remainder > 0:
                    remainder -= 1
                chunk = wordlist[start_index:end_index]
                futures.append(executor.submit(check_password, entry, chunk))
                start_index = end_index

        for future in futures:
            result = future.result()
            if result:
                user, found_password = result
                print(f"Password for {user} found: {found_password}")
                logger.info(f"Password for {user} found: {found_password}")


def profile_function(function, *args, **kwargs):
    """Utility function to profile another function."""
    pr = cProfile.Profile()
    pr.enable()
    result = function(*args, **kwargs)
    pr.disable()
    s = io.StringIO()
    ps = pstats.Stats(pr, stream=s).sort_stats('cumulative')
    ps.print_stats()
    logger.info(s.getvalue())
    return result


def parse_args():
    """Parse command line arguments for the script."""
    parser = argparse.ArgumentParser(description="Password Cracking Script")
    parser.add_argument('--wordlist', type=str, required=True,
                        help='Path to the wordlist file.')
    parser.add_argument('--shadow', type=str, required=True,
                        help='Path to the shadow data file.')
    return parser.parse_args()


def main():
    args = parse_args()

    # Load the wordlist
    wordlist = load_wordlist(args.wordlist)

    # Load the shadow data
    try:
        with open(args.shadow, 'r') as file:
            shadow_data = json.load(file)
    except Exception as e:
        logger.error(f"Failed to load shadow data: {e}")
        return

    # Start the timer
    start_time = time.time()

    # Start cracking passwords with profiling
    profile_function(crack_passwords, shadow_data, wordlist)

    # Log the total execution time
    end_time = time.time()
    logger.info(f"Total execution time: {end_time - start_time:.2f} seconds")


if __name__ == "__main__":
    main()

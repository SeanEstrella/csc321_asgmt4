import logging
import signal
import sys
import time

import bcrypt

# Configure logging
logging.basicConfig(filename='password_cracking.log', level=logging.INFO,
                    format='%(asctime)s:%(levelname)s:%(message)s')

# Global variable to track the last tried password
last_tried_password = None


def load_wordlist(filename):
    """ Load the wordlist from a file, assuming one word per line, encoded in UTF-8."""
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as file:
            return [line.strip().encode('utf-8') for line in file if line.strip()]
    except Exception as e:
        logging.error(f"Failed to load wordlist: {e}")
        return []


def signal_handler(sig, frame):
    """ Handle the KeyboardInterrupt signal to log progress before shutting down. """
    logging.info(
        f"Script interrupted! Last tried password: {last_tried_password.decode() if last_tried_password else 'None'}")
    sys.exit(0)


def crack_passwords(shadow_data, wordlist):
    """ Attempt to find the original plaintext passwords for the given bcrypt hashes using a wordlist. """
    global last_tried_password
    for entry in shadow_data:
        user = entry['user']
        hashed = entry['hash'].encode('utf-8')
        found = False
        for password in wordlist:
            last_tried_password = password  # Update the global variable
            if bcrypt.checkpw(password, hashed):
                print(f"Password for {user} found: {password.decode()}")
                logging.info(f"Password for {user} found: {password.decode()}")
                found = True
                break  # Break if password is found, move to next user
        if not found:
            logging.info(f"Password for {user} not found.")


# Setup signal handler for KeyboardInterrupt
signal.signal(signal.SIGINT, signal_handler)

# Example shadow data
shadow_data = [
    {"user": "Dwalin", "hash": "$2b$10$xGKjb94iwmlth954hEaw3OFxNMF64erUqDNj6TMMKVDcsETsKK5be"},
    {"user": "Oin", "hash": "$2b$10$xGKjb94iwmlth954hEaw3OcXR2H2PRHCgo98mjS11UIrVZLKxyABK"},
    {"user": "Gloin", "hash": "$2b$11$/8UByex2ktrWATZOBLZ0DuAXTQl4mWX1hfSjliCvFfGH7w1tX5/3q"},
    {"user": "Dori", "hash": "$2b$11$/8UByex2ktrWATZOBLZ0Dub5AmZeqtn7kv/3NCWBrDaRCFahGYyiq"},
    {"user": "Nori", "hash": "$2b$11$/8UByex2ktrWATZOBLZ0DuER3Ee1GdP6f30TVIXoEhvhQDwghaU12"},
    {"user": "Ori", "hash": "$2b$12$rMeWZtAVcGHLEiDNeKCz8OiERmh0dh8AiNcf7ON3O3P0GWTABKh0O"},
    {"user": "Bifur", "hash": "$2b$12$rMeWZtAVcGHLEiDNeKCz8OMoFL0k33O8Lcq33f6AznAZ/cL1LAOyK"},
    {"user": "Bofur", "hash": "$2b$12$rMeWZtAVcGHLEiDNeKCz8Ose2KNe821.l2h5eLffzWoP01DlQb72O"},
    {"user": "Durin", "hash": "$2b$13$6ypcazOOkUT/a7EwMuIjH.qbdqmHPDAC9B5c37RT9gEw18BX6FOay"}
]

# Load the wordlist - specify the path to your wordlist file
wordlist = load_wordlist('pwlist_part_01')

# Start the timer
start_time = time.time()

# Start cracking passwords
crack_passwords(shadow_data, wordlist)

# Log the total execution time
end_time = time.time()
logging.info(f"Total execution time: {end_time - start_time:.2f} seconds")

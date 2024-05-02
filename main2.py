import bcrypt
import logging
import time

# Configure logging
logging.basicConfig(filename='password_cracking.log', level=logging.INFO,
                    format='%(asctime)s:%(levelname)s:%(message)s')


def load_wordlist(filename):
    """ Load the wordlist from a file, assuming one word per line, encoded in UTF-8."""
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as file:
            return [line.strip().encode('utf-8') for line in file if line.strip()]
    except Exception as e:
        logging.error(f"Failed to load wordlist: {e}")
        return []


def crack_passwords(shadow_data, wordlist):
    """ Attempt to find the original plaintext passwords for the given bcrypt hashes using a wordlist. """
    for entry in shadow_data:
        user = entry['user']
        hashed = entry['hash'].encode('utf-8')
        found = False
        for password in wordlist:
            if bcrypt.checkpw(password, hashed):
                print(f"Password for {user} found: {password.decode()}")
                logging.info(f"Password for {user} found: {password.decode()}")
                found = True
                break  # Break if password is found, move to next user
        if not found:
            logging.info(f"Password for {user} not found.")


# Example shadow data
shadow_data = [
    {"user": "Balin", "hash": "$2b$10$xGKjb94iwmlth954hEaw3O3YmtDO/mEFLIO0a0xLK1vL79LA73Gom"},
]

# Load the wordlist - specify the path to your wordlist file
# wordlist = load_wordlist('SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt')
wordlist = load_wordlist('10-million-password-list-top-1000000.txt')

# Start the timer
start_time = time.time()

# Start cracking passwords
crack_passwords(shadow_data, wordlist)

# Log the total execution time
end_time = time.time()
logging.info(f"Total execution time: {end_time - start_time:.2f} seconds")

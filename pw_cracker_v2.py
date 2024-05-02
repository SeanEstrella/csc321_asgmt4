import logging
import time
from multiprocessing import Pool, cpu_count

import bcrypt
import nltk
from nltk.corpus import words

# Ensure NLTK data is downloaded
nltk.download('words')

# Configure logging
logging.basicConfig(filename='password_cracking.log', level=logging.INFO,
                    format='%(asctime)s:%(levelname)s:%(message)s')


def load_wordlist():
    """ Load words from the NLTK words corpus, filtered by length between 6 and 10 letters. """
    return [word.encode('utf-8') for word in words.words() if 6 <= len(word) <= 10]


def check_password(args):
    """ Attempt to match the password against the provided bcrypt hash. """
    user, full_hash, password = args
    if bcrypt.checkpw(password, full_hash):
        return user, password.decode()
    return None


def crack_passwords(shadow_data, wordlist):
    """ Use multiprocessing to attempt to find the original plaintext passwords. """
    args = [(user, full_hash, password) for user, full_hash in shadow_data for password in wordlist]
    with Pool(cpu_count()) as pool:
        results = pool.map(check_password, args)
    for result in filter(None, results):
        user, password = result
        print(f"Password for {user} found: {password}")
        logging.info(f"Password for {user} found: {password}")


def main():
    # Hardcoded shadow data
    shadow_data = [
        ("Bilbo", "$2b$08$J9FW66ZdPI2nrIMcOxFYI.qx268uZn.ajhymLP/YHaAsfBGP3Fnmq".encode('utf-8')),
        ("Gandalf", "$2b$08$J9FW66ZdPI2nrIMcOxFYI.q2PW6mqALUl2/uFvV9OFNPmHGNPa6YC".encode('utf-8')),
        ("Thorin", "$2b$08$J9FW66ZdPI2nrIMcOxFYI.6B7jUcPdnqJz4tIUwKBu8lNMs5NdT9q".encode('utf-8')),
        ("Fili", "$2b$09$M9xNRFBDn0pUkPKIVCSBzuwNDDNTMWlvn7lezPr8IwVUsJbys3YZm".encode('utf-8')),
        ("Kili", "$2b$09$M9xNRFBDn0pUkPKIVCSBzuPD2bsU1q8yZPlgSdQXIBILSMCbdE4Im".encode('utf-8')),
        ("Balin", "$2b$10$xGKjb94iwmlth954hEaw3O3YmtDO/mEFLIO0a0xLK1vL79LA73Gom".encode('utf-8')),
        ("Dwalin", "$2b$10$xGKjb94iwmlth954hEaw3OFxNMF64erUqDNj6TMMKVDcsETsKK5be".encode('utf-8')),
        ("Oin", "$2b$10$xGKjb94iwmlth954hEaw3OcXR2H2PRHCgo98mjS11UIrVZLKxyABK".encode('utf-8')),
        ("Gloin", "$2b$11$/8UByex2ktrWATZOBLZ0DuAXTQl4mWX1hfSjliCvFfGH7w1tX5/3q".encode('utf-8')),
        ("Dori", "$2b$11$/8UByex2ktrWATZOBLZ0Dub5AmZeqtn7kv/3NCWBrDaRCFahGYyiq".encode('utf-8')),
        ("Nori", "$2b$11$/8UByex2ktrWATZOBLZ0DuER3Ee1GdP6f30TVIXoEhvhQDwghaU12".encode('utf-8')),
        ("Ori", "$2b$12$rMeWZtAVcGHLEiDNeKCz8OiERmh0dh8AiNcf7ON3O3P0GWTABKh0O".encode('utf-8')),
        ("Bifur", "$2b$12$rMeWZtAVcGHLEiDNeKCz8OMoFL0k33O8Lcq33f6AznAZ/cL1LAOyK".encode('utf-8')),
        ("Bofur", "$3b$12$rMeWZtAVcGHLEiDNeKCz8Ose2KNe821.l2h5eLffzWoP01DlQb72O".encode('utf-8')),
        ("Durin", "$2b$13$6ypcazOOkUT/a7EwMuIjH.qbdqmHPDAC9B5c37RT9gEw18BX6FOay".encode('utf-8'))
    ]
    # Load the wordlist from NLTK
    wordlist = load_wordlist()

    # Start the timer
    start_time = time.time()

    # Start cracking passwords using multiprocessing
    crack_passwords(shadow_data, wordlist)

    # Log the total execution time
    end_time = time.time()
    logging.info(f"Total execution time: {end_time - start_time:.2f} seconds")


if __name__ == "__main__":
    main()

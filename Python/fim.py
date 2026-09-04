import hashlib
import time
import os

files_to_monitor = ["/etc/passwd", "/etc/shadow"]
hash_dict = {}

def get_file_hash(file_path):
    with open(file_path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()

def initialize_hashes():
    for file in files_to_monitor:
        hash_dict[file] = get_file_hash(file)

def check_integrity():
    for file, initial_hash in hash_dict.items():
        if not os.path.exists(file):
            print(f"{file} not found!!!")
            continue

        current_hash = get_file_hash(file)
        if current_hash != initial_hash:
            print(f"A change has been detected in {file}!")


initialize_hashes()

while True:
    check_integrity()
    time.sleep(3600)
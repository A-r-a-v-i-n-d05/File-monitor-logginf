import os
import hashlib
import json
import time
from datetime import datetime

WATCH_PATHS = [
    "/etc",          
    "/home/arav1nd/monitor_me"  
]

HASH_DB = "file_hashes.json"
LOG_FILE = "fim_alerts.log"
SCAN_INTERVAL = 10   # seconds

def calculate_hash(filepath): #filepath - file to calculate hash mentioned in the directory
    sha256 = hashlib.sha256() #sha256 hash is being used hahlib
    try:
        with open(filepath, "rb") as f: # open the file in binary mode
            for chunk in iter(lambda: f.read(4096), b""): # anonymous function that reads next 4096 bytes of data , iter function runs the lambda function till it encounters b"" -empty string
                sha256.update(chunk) #each hash is getting updated
        return sha256.hexdigest() # final hash is returned
    except FileNotFoundError: # error handling 
        return None

def load_hash_db():
    if not os.path.exists(HASH_DB): # if file doesn't exists then nothing loaded
        return {} 
    with open(HASH_DB, "r") as f:# if file exists opened in read mode
        return json.load(f) # returns the format in python dict 


def save_hash_db(db): # db-contains updated hashes 
    with open(HASH_DB, "w") as f: #opeen the folder in write mode to append the modified hashes
        json.dump(db, f, indent=4)#dump the hashes received 


def log_event(event_type, filepath): 
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S") # calculate timestamp
    entry = f"{timestamp}  |  {event_type}  |  {filepath}\n" # formatting the entry

    with open(LOG_FILE, "a") as log: # opens file in append mode
        log.write(entry) # writes to the file                     
    print(entry.strip()) # printing in the terminal for debugging

def scan_files():
    file_hashes = load_hash_db()
    current_hashes = {}

    # Walk through all paths
    for base_path in WATCH_PATHS:
        for root, dirs, files in os.walk(base_path):
            for fname in files:
                filepath = os.path.join(root, fname)
                file_hash = calculate_hash(filepath)

                if file_hash:
                    current_hashes[filepath] = file_hash

                    # file modified
                    if filepath in file_hashes:
                        if file_hash != file_hashes[filepath]:
                            log_event("MODIFIED", filepath)
                    else:
                        # new file created
                        log_event("CREATED", filepath)

    # file deleted
    for old_file in file_hashes:
        if old_file not in current_hashes:
            log_event("DELETED", old_file)

    save_hash_db(current_hashes)

def main():
    print("File Integrity Monitoring Started...")
    print(f"Monitoring paths: {WATCH_PATHS}")
    while True:
        scan_files()
        time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    main()

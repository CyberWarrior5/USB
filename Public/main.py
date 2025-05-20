# Save the previous cryptography class code as Modules/file_cryptography.py
# Ensure your project structure is like:
# your_script.py
# config.json
# Modules/
#     __init__.py (can be empty)
#     file_cryptography.py

from Modules.file_cryptography import file_cryptography
import win32api
import win32file
import json
import os
import sys
from tqdm import tqdm # Import tqdm
# import time # Still potentially useful for pauses on errors, though not strictly necessary for tqdm

def usb_drive(label: str):
    """
    Finds the drive letter for a removable drive with a specific label.
    """
    try:
        drives = win32api.GetLogicalDriveStrings().split('\u0000')[:-1]
        for drive in drives:
            try:
                # Check if it's a removable drive
                if win32file.GetDriveType(drive) == win32file.DRIVE_REMOVABLE:
                    # Get volume information, including label
                    volume_info = win32api.GetVolumeInformation(drive)
                    volume_label = volume_info[0]
                    # Compare labels (case-insensitive)
                    if volume_label and volume_label.lower() == label.lower():
                        # Return the drive letter, e.g., "G:\"
                        # Ensure it has a trailing slash for consistent path joining later
                        return drive + "\\"

            except Exception:
                # Ignore errors for specific drives (e.g., empty card reader slots)
                continue

    except Exception as e:
        print(f"[-] USB detection error: {e}", file=sys.stderr)

    return None # Return None if no matching drive is found

def count_processable_files(drive_letter: str, mode: str):
    """
    Counts the number of files that will be subject to encryption or decryption
    based on the mode, applying the skipping/resumable logic.
    """
    count = 0
    print(f"[*] Counting files to {mode}...")

    # Walk the entire drive
    for root, dirs, files in os.walk(drive_letter, followlinks=False):
        # Sort files and directories for potentially consistent processing order
        files.sort()
        dirs.sort()

        for file in files:
            original_path = os.path.join(root, file)

            if mode == 'encrypt':
                # --- Encrypt Mode Counting Logic ---
                # Skip files that are the encryption output types (.enc, .salt)
                if file.lower().endswith(('.enc', '.salt')):
                    continue

                # Check if the corresponding .enc and .salt files already exist in the same directory
                encrypted_path = original_path + ".enc"
                salt_path = original_path + ".salt"
                if os.path.exists(encrypted_path) and os.path.exists(salt_path):
                    continue # Skip if already encrypted

                # If we reach here in encrypt mode, it's a file we WILL attempt to encrypt
                count += 1

            elif mode == 'decrypt':
                # --- Decrypt Mode Counting Logic ---
                # We only care about .enc files as the starting point for decryption
                if not file.lower().endswith('.enc'):
                    continue # Skip if not an encrypted file

                # Check for the corresponding .salt file
                salt_path = original_path[:-4] + ".salt" # Assumes .enc extension
                # Check if the derived original filename would be empty (e.g., if file was just ".enc")
                if not salt_path.endswith(".salt"):
                     # This means original_path didn't end with .enc or was too short
                     # Should not happen with standard naming but defensive check
                     continue

                if not os.path.exists(salt_path):
                    # This .enc file doesn't have a corresponding .salt from our process
                    # print(f"[*] Warning: Skipping orphaned .enc file (no matching .salt): {original_path}", file=sys.stderr)
                    continue # Skip if no matching salt

                # Determine the expected original filename
                original_filename = file[:-4] # Remove .enc extension
                 # Check if original filename is empty after removing extension (e.g., file was ".enc")
                if not original_filename:
                    # Skip files like ".enc", "file..enc" etc.
                    continue

                original_file_path = os.path.join(root, original_filename) # Path for the decrypted output

                # Check if the original file already exists (meaning it was successfully decrypted)
                if os.path.exists(original_file_path):
                    continue # Skip if already decrypted

                # If we reach here in decrypt mode, it's a file we WILL attempt to decrypt
                count += 1
            else:
                # Should not happen if input validation is correct, but good practice
                raise ValueError(f"Internal Error: Invalid mode '{mode}' passed to count_processable_files")

    print(f"[*] Found {count} files to {mode}.")
    return count


def main():
    # --- 1. Get User Input for Mode ---
    mode = None
    while mode not in ['encrypt', 'decrypt']:
        user_input = input("Do you want to (e)ncrypt or (d)ecrypt the USB? (e/d): ").lower()
        if user_input == 'e' or user_input == 'encrypt':
            mode = 'encrypt'
        elif user_input == 'd' or user_input == 'decrypt':
            mode = 'decrypt'
        else:
            print("Invalid input. Please enter 'e', 'encrypt', 'd', or 'decrypt'.")

    # --- 2. Read Configuration ---
    config = {}
    try:
        with open("config.json", 'r') as f:
            config = json.load(f)
            drive_label = config.get("drive_label")

            if not drive_label:
                 print("Error: 'drive_label' not found in config.json", file=sys.stderr)
                 sys.exit(1)

    except FileNotFoundError:
        print("Error: config.json not found.", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError:
        print("Error: Could not parse config.json. Check for syntax errors.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading config.json: {e}", file=sys.stderr)
        sys.exit(1)

    # --- 3. Find USB Drive ---
    print(f"[*] Looking for USB drive with label: '{drive_label}'")
    drive_letter = usb_drive(drive_label)

    if not drive_letter:
        print(f"[-] USB drive with label '{drive_label}' not found. Exiting.", file=sys.stderr)
        sys.exit(1)

    # drive_letter already has trailing slash from usb_drive function

    print(f"[*] Found USB drive: {drive_letter}")

    # --- 4. Initialize the cryptography session (prompts for password ONCE) ---
    print(f"\n[*] Setting up cryptography session for {mode}ion...")
    crypto_session = None
    try:
        crypto_session = file_cryptography()
        print(f"[+] Cryptography session initialized successfully for {mode}ion.")
    except SystemExit:
        # The file_cryptography __init__ handles password mismatch and exits
        print("[-] Failed to initialize cryptography session. Exiting.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[-] Unexpected error during cryptography setup: {e}", file=sys.stderr)
        sys.exit(1)
    # -----------------------------------------------------------------------

    # --- 5. Count total files to process based on mode ---
    total_files_to_process = count_processable_files(drive_letter, mode)

    processed_count = 0 # Count of files visited in the main loop (matches pbar updates)
    success_count = 0 # Encrypted or Decrypted successfully and cleanup done
    skipped_count = 0
    failed_count = 0

    if total_files_to_process == 0:
        print(f"[*] No files found requiring {mode}ion. Exiting.")
        sys.exit(0)

    # --- 6. Start Processing Loop ---
    print(f"\n[*] Starting {mode}ion process...")
    # Initialize tqdm progress bar
    with tqdm(total=total_files_to_process, desc=f"{mode.capitalize()}ing USB", unit=" files", leave=True) as pbar:
        # Walk through all files and directories on the drive
        for root, dirs, files in os.walk(drive_letter, followlinks=False):
            # Sort files and directories for consistent processing order
            files.sort()
            dirs.sort()

            # Process files in the current directory
            for file in files:
                original_full_path = os.path.join(root, file)

                if mode == 'encrypt':
                    # --- Encrypt Mode Processing ---
                    # Skip files that are the encryption output types (.enc, .salt)
                    if file.lower().endswith(('.enc', '.salt')):
                         continue # Skip these files entirely

                    # Determine target paths (in the same directory)
                    encrypted_path = original_full_path + ".enc"
                    salt_path = original_full_path + ".salt"

                    # Resumable Logic: Check if file is already successfully encrypted
                    if os.path.exists(encrypted_path) and os.path.exists(salt_path):
                         tqdm.write(f"[*] Skipping file (already appears encrypted): {original_full_path}")
                         skipped_count += 1
                         pbar.update(1) # Increment pbar for the skipped file (as it was included in the total count)
                         continue # Move to the next file

                    # Cleanup potential incomplete files from previous failed attempt
                    if os.path.exists(encrypted_path) or os.path.exists(salt_path):
                         tqdm.write(f"[*] Found incomplete files from previous attempt for: {original_full_path}. Cleaning up...")
                         try:
                             if os.path.exists(encrypted_path):
                                 tqdm.write(f"    - Removing incomplete .enc: {encrypted_path}")
                                 os.remove(encrypted_path)
                             if os.path.exists(salt_path):
                                 tqdm.write(f"    - Removing incomplete .salt: {salt_path}")
                                 os.remove(salt_path)
                         except OSError as e:
                             tqdm.write(f"[-] Warning: Could not clean up old incomplete files for '{original_full_path}': {e}. Skipping this file.", file=sys.stderr)
                             failed_count += 1
                             pbar.update(1) # Increment pbar for the failed file
                             continue # Skip this file as we couldn't clean up previous attempt files

                    # --- Proceed with Encryption ---
                    pbar.set_description(f"Encrypting: {file[:50]}...") # Truncate long filenames
                    tqdm.write(f"[*] Encrypting: {original_full_path}") # Print before attempt

                    try:
                        # Perform the encryption using the session object
                        # Output goes to original_full_path + ".enc" and original_full_path + ".salt"
                        # The encrypt_file method's internal error handling will clean up
                        # the destination files (.enc and .salt) if an error occurs *after*
                        # they are opened.
                        crypto_session.encrypt_file(original_full_path, encrypted_path, salt_path)

                        tqdm.write(f"[+] Successfully encrypted '{file}'.")

                        # --- Delete the original file after successful encryption ---
                        try:
                            os.remove(original_full_path)
                            tqdm.write(f"[+] Deleted original file: {original_full_path}")
                            success_count += 1 # Count as successful if original is successfully deleted
                        except OSError as e:
                            # If deletion fails, report it as a failure
                            tqdm.write(f"[-] Error: Could not delete original file '{original_full_path}' AFTER successful encryption: {e}", file=sys.stderr)
                            failed_count += 1 # Count this as a failure because cleanup wasn't complete


                    except SystemExit:
                        # Catch SystemExit from file_cryptography method (e.g., file error during crypto)
                        failed_count += 1
                        tqdm.write(f"[-] Encryption failed for '{file}'. See previous error message.", file=sys.stderr)
                    except Exception as e:
                         # Catch any other unexpected errors during encryption processing
                         failed_count += 1
                         tqdm.write(f"[-] An unexpected error occurred processing '{file}': {e}", file=sys.stderr)

                    # Increment the progress bar *after* attempting to process the file
                    pbar.update(1)


                elif mode == 'decrypt':
                    # --- Decrypt Mode Processing ---
                    # We only process .enc files
                    if not file.lower().endswith('.enc'):
                        continue # Skip if not an encrypted file (.enc)

                    # Determine expected paths for salt and original file
                    encrypted_full_path = original_full_path # Rename variable for clarity in decrypt mode
                    # Ensure original filename isn't empty after removing extension
                    original_filename = file[:-4] if file.lower().endswith('.enc') and len(file) > 4 else None
                    if not original_filename:
                        # Skip files like ".enc", "file..enc", "file" (no .enc), etc.
                        continue

                    salt_path = os.path.join(root, original_filename + ".salt") # Path for the salt file
                    original_file_path = os.path.join(root, original_filename) # Path for the decrypted output

                    # Check for the corresponding .salt file
                    if not os.path.exists(salt_path):
                         # This .enc file doesn't have a corresponding .salt from our process
                         # This should not be counted in total_files_to_process, but handle defensively
                         # tqdm.write(f"[*] Skipping orphaned .enc file (no matching .salt): {encrypted_full_path}", file=sys.stderr)
                         # Don't update pbar as this wasn't included in the count
                         continue # Skip if no matching salt

                    # Resumable Logic: Check if the original file already exists (meaning it was successfully decrypted)
                    if os.path.exists(original_file_path):
                         tqdm.write(f"[*] Skipping file pair (.enc/.salt) (already appears decrypted): {encrypted_full_path}")
                         skipped_count += 1
                         pbar.update(1) # Increment pbar for the skipped pair
                         continue # Move to the next file

                    # Cleanup potential incomplete original file from previous failed decryption attempt
                    # We don't need to clean up the .enc/.salt pair here, decrypt_file handles partial original output
                    if os.path.exists(original_file_path):
                         tqdm.write(f"[*] Found incomplete original file from previous attempt: {original_file_path}. Cleaning up...")
                         try:
                             tqdm.write(f"    - Removing incomplete original: {original_file_path}")
                             os.remove(original_file_path)
                         except OSError as e:
                             tqdm.write(f"[-] Warning: Could not clean up old incomplete original file '{original_file_path}': {e}. Skipping this pair.", file=sys.stderr)
                             failed_count += 1
                             pbar.update(1) # Increment pbar for the failed pair
                             continue # Skip this pair as we couldn't clean up previous attempt file


                    # --- Proceed with Decryption ---
                    pbar.set_description(f"Decrypting: {file[:50]}...") # Truncate long filenames
                    tqdm.write(f"[*] Decrypting: {encrypted_full_path}") # Print before attempt

                    try:
                        # Perform the decryption using the session object
                        # Output goes to original_file_path
                        # The decrypt_file method's internal error handling will clean up
                        # the destination file (original_file_path) if an error occurs *after*
                        # it's opened (especially InvalidTag).
                        crypto_session.decrypt_file(encrypted_full_path, original_file_path, salt_path)

                        tqdm.write(f"[+] Successfully decrypted '{file}'.")

                        # --- Delete the encrypted files (.enc and .salt) after successful decryption ---
                        try:
                            os.remove(encrypted_full_path)
                            os.remove(salt_path)
                            tqdm.write(f"[+] Deleted encrypted files: {encrypted_full_path} and {salt_path}")
                            success_count += 1 # Count as successful if encrypted files are successfully deleted
                        except OSError as e:
                            # If deletion fails, report it as a failure
                            tqdm.write(f"[-] Error: Could not delete encrypted files for '{file}' AFTER successful decryption: {e}", file=sys.stderr)
                            failed_count += 1 # Count this as a failure because cleanup wasn't complete

                    except SystemExit:
                        # Catch SystemExit from file_cryptography method (e.g., InvalidTag, file error)
                        failed_count += 1
                        tqdm.write(f"[-] Decryption failed for '{file}'. See previous error message.", file=sys.stderr)
                    except Exception as e:
                         # Catch any other unexpected errors during decryption processing
                         failed_count += 1
                         tqdm.write(f"[-] An unexpected error occurred processing '{file}': {e}", file=sys.stderr)

                    # Increment the progress bar *after* attempting to process the file pair
                    # We only counted the .enc file in total_files_to_process, so increment by 1
                    pbar.update(1)
                # End of if/elif mode checks

    # --- 7. Print Summary ---
    print(f"\n[*] {mode.capitalize()}ion process finished.")
    print(f"Summary:")
    print(f"  Files considered (total):   {total_files_to_process}")
    print(f"  Files successfully handled: {success_count}")
    print(f"  Files skipped (already done): {skipped_count}")
    print(f"  Files failed (this run):    {failed_count}")
    # Add a check if the counts add up (might not if orphaned .enc files were skipped without pbar update)
    if success_count + skipped_count + failed_count != total_files_to_process:
         print(f"Warning: Count mismatch: {success_count + skipped_count + failed_count} != {total_files_to_process}. This might be due to orphaned files skipped during count.", file=sys.stderr)


if __name__ == "__main__":
    main()
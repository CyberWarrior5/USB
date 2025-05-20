from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
from cryptography.exceptions import InvalidTag
import os
import sys
import getpass

class file_cryptography:

    def __init__(self):
        """
        Initializes the file_cryptography object by prompting for and storing
        the user's password for the session.
        """
        try:
            # Prompt for password only once when the object is created
            password = getpass.getpass("Enter password for this session: ").encode()
            password_check = getpass.getpass("Enter password again: ").encode()

            if password != password_check:
                print("Error: Passwords do not match.", file=sys.stderr)
                sys.exit(1)

            # Store the password bytes securely in the instance
            self._password = password

            # Note: In this design, the password itself doesn't have a stored
            # 'master' salt. The salt used in derive_key is a *per-file* salt,
            # generated uniquely for each file encryption and stored alongside it.

        except Exception as e:
            print(f"Error during password setup: {e}", file=sys.stderr)
            sys.exit(1)

    def derive_key(self, password, salt):
        """
        Derives a cryptographic key from a password and a salt using PBKDF2HMAC.
        """
        length = 32 # AES key size
        iterations = 5_000_000 # High iteration count for security
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            salt=salt,
            length=length,
            iterations=iterations
        )

        try:
            # password here is self._password passed from encrypt/decrypt
            # salt is the per-file salt read from or written to salt_path
            key = kdf.derive(password)
            return key
        except Exception as e:
            # Catch potential issues during derivation, though rare with valid inputs
            print(f"Error deriving key: {e}", file=sys.stderr)
            sys.exit(1)


    def encrypt_file(self, file_path, dest_path, salt_path):
        """
        Encrypts a file using AES-GCM with a key derived from the instance's
        password and a new, unique salt for this file.
        """
        dest_file_created = False # Flag to track if output file was successfully opened
        try:
            # Generate a unique salt and IV for this file
            salt = os.urandom(16) # Standard salt size for PBKDF2
            iv = os.urandom(12) # GCM recommended IV size

            # Use the instance's password and the new file salt to derive the key
            key = self.derive_key(self._password, salt)

            # Store the file-specific salt
            try:
                with open(salt_path, 'wb') as f:
                    f.write(salt)
            except (FileNotFoundError, PermissionError, IOError) as e:
                 print(f"Error writing salt file '{salt_path}': {e}", file=sys.stderr)
                 # Clean up the derived key from memory (though it's garbage collected)
                 # and signal failure. No dest file created yet, so no cleanup there.
                 sys.exit(1)

            cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
            encryptor = cipher.encryptor()

            try:
                # Open input and output files
                with open(file_path, 'rb') as infile, open(dest_path, 'wb') as outfile:
                    dest_file_created = True # Output file is open, mark as created
                    outfile.write(iv) # Write IV at the beginning

                    # Encrypt and write data in chunks
                    while chunk := infile.read(8192):
                        outfile.write(encryptor.update(chunk))

                    # Finalize encryption and write the authentication tag
                    outfile.write(encryptor.finalize())
                    outfile.write(encryptor.tag) # Write the tag at the end

            except (FileNotFoundError, PermissionError, IOError) as e:
                 # Catch errors during file read/write operations
                 print(f"File error during encryption: {e}", file=sys.stderr)
                 # Cleanup happens in the outer except block via the 'raise'
                 raise # Re-raise the exception to trigger the cleanup block

            except Exception as e:
                # Catch any other unexpected errors during the encryption process
                print(f"An unexpected error occurred during encryption: {e}", file=sys.stderr)
                # Cleanup happens in the outer except block via the 'raise'
                raise # Re-raise the exception to trigger the cleanup block


        except Exception: # This block catches exceptions re-raised from the inner try block
            # Clean up the destination file if it was created but the process failed
            if dest_file_created and os.path.exists(dest_path):
                print(f"Cleaning up incomplete file: '{dest_path}'", file=sys.stderr)
                try:
                    os.remove(dest_path)
                except OSError as e:
                    # If we can't even remove the incomplete file, just report it
                    print(f"Error removing incomplete file '{dest_path}': {e}", file=sys.stderr)
            sys.exit(1) # Exit indicating failure

    def decrypt_file(self, file_path, dest_path, salt_path):
        """
        Decrypts a file encrypted with AES-GCM using the instance's password
        and the salt stored in the salt file.
        """
        dest_file_created = False # Flag to track if output file was successfully opened
        try:
            # Read the file-specific salt
            try:
                with open(salt_path, 'rb') as f:
                    salt = f.read()
                if len(salt) != 16: # Basic check for expected salt size
                     print(f"Error: Salt file '{salt_path}' has incorrect size.", file=sys.stderr)
                     sys.exit(1)
            except (FileNotFoundError, PermissionError, IOError) as e:
                print(f"Error reading salt file '{salt_path}': {e}", file=sys.stderr)
                sys.exit(1)
            except Exception as e:
                 print(f"An unexpected error occurred reading salt file: {e}", file=sys.stderr)
                 sys.exit(1)


            # Get the size of the encrypted file
            try:
                file_size = os.path.getsize(file_path)
            except (FileNotFoundError, PermissionError, OSError) as e:
                 print(f"Error getting size of input file '{file_path}': {e}", file=sys.stderr)
                 sys.exit(1)

            # Open the encrypted file to read IV and Tag
            try:
                with open(file_path, "rb") as fin:
                    # Check if file is too small to contain IV and tag (12 + 16 bytes)
                    if file_size < 12 + 16:
                         print(f"Error: File '{file_path}' is too small to be a valid encrypted file.", file=sys.stderr)
                         sys.exit(1)

                    # Read IV
                    iv = fin.read(12)
                    if len(iv) != 12:
                        print(f"Error: Could not read IV from '{file_path}'. File format incorrect?", file=sys.stderr)
                        sys.exit(1)

                    # Calculate ciphertext length
                    cipher_text_length = file_size - 12 - 16

                    # Record the position where ciphertext starts
                    ciphertext_start = fin.tell()

                    # Seek to the position of the tag (16 bytes from the end) and read it
                    fin.seek(-16, os.SEEK_END)
                    tag = fin.read(16)
                    if len(tag) != 16:
                         print(f"Error: Could not read tag from '{file_path}'. File format incorrect?", file=sys.stderr)
                         sys.exit(1)

            except (FileNotFoundError, PermissionError, IOError) as e:
                 print(f"File error reading encrypted file header/footer '{file_path}': {e}", file=sys.stderr)
                 sys.exit(1)
            except Exception as e:
                 # Catch other potential errors during header/tag reading
                 print(f"An unexpected error occurred reading encrypted file header/footer: {e}", file=sys.stderr)
                 sys.exit(1)

            # Use the instance's password and the file salt to derive the key
            key = self.derive_key(self._password, salt)

            # Prepare the cipher for decryption using the derived key, IV, and tag
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
            decryptor = cipher.decryptor()

            # Re-open files to stream decryption
            try:
                with open(file_path, "rb") as fin, open(dest_path, "wb") as fout:
                    dest_file_created = True # Output file is open, mark as created
                    fin.seek(ciphertext_start) # Start reading from where the ciphertext begins

                    total_read = 0
                    chunk_size = 8192

                    # Decrypt and write data in chunks
                    while total_read < cipher_text_length:
                        to_read = min(chunk_size, cipher_text_length - total_read)
                        chunk = fin.read(to_read)
                        if not chunk and to_read > 0: # Handle unexpected end of file
                            print(f"Error: Unexpected end of encrypted file '{file_path}'. File may be truncated.", file=sys.stderr)
                            # Cleanup happens in the outer except block via the 'raise'
                            raise IOError("Unexpected end of file")

                        decrypted_chunk = decryptor.update(chunk)
                        fout.write(decrypted_chunk)
                        total_read += len(chunk)

                    # Finalize decryption. This verifies the GCM tag.
                    # If verification fails, an InvalidTag exception is raised.
                    fout.write(decryptor.finalize())

            except InvalidTag:
                 # This specific exception indicates the tag verification failed,
                 # usually due to incorrect password or file corruption/tampering.
                 print("Decryption failed: Incorrect password or file is corrupted/tampered.", file=sys.stderr)
                 # Cleanup happens in the outer except block via the 'raise'
                 raise # Re-raise to trigger outer except block cleanup

            except (FileNotFoundError, PermissionError, IOError) as e:
                 # Catch errors during file read/write loop
                 print(f"File error during decryption: {e}", file=sys.stderr)
                 # Cleanup happens in the outer except block via the 'raise'
                 raise # Re-raise to trigger outer except block cleanup

            except Exception as e:
                # Catch any other unexpected errors during decryption loop
                print(f"An unexpected error occurred during decryption: {e}", file=sys.stderr)
                # Cleanup happens in the outer except block via the 'raise'
                raise # Re-raise to trigger outer except block cleanup

        except Exception: # This block catches exceptions re-raised from the inner try blocks
            # Clean up the destination file if it was created but the process failed
            if dest_file_created and os.path.exists(dest_path):
                print(f"Cleaning up incomplete file: '{dest_path}'", file=sys.stderr)
                try:
                    os.remove(dest_path)
                except OSError as e:
                    # If we can't even remove the incomplete file, just report it
                     print(f"Error removing incomplete file '{dest_path}': {e}", file=sys.stderr)
            sys.exit(1) # Exit indicating failure


# Example Usage (optional)
if __name__ == '__main__':
    # Create an instance of the class - this prompts for the password once
    print("Setting up the cryptography session...")
    try:
        crypto = file_cryptography()
        print("Cryptography object created. Password set for this session.")
    except SystemExit:
        print("Password setup failed. Exiting.", file=sys.stderr)
        sys.exit(1)


    # --- Setup test files ---
    dummy_file_path = "test_plain.txt"
    encrypted_file_path = "test_encrypted.bin"
    decrypted_file_path = "test_decrypted.txt"
    salt_file_path = "test_salt.bin"

    try:
        with open(dummy_file_path, "w") as f:
            f.write("This is a test file.\n")
            f.write("It contains some sample data.\n")
            f.write("Let's see if it encrypts and decrypts correctly.\n")
        print(f"\nCreated dummy file: '{dummy_file_path}'")

        # --- Test Encryption ---
        print(f"\nEncrypting '{dummy_file_path}' to '{encrypted_file_path}'...")
        try:
            crypto.encrypt_file(dummy_file_path, encrypted_file_path, salt_file_path)
            print("Encryption successful.")
        except SystemExit:
            print("Encryption failed.", file=sys.stderr)


        # --- Test Decryption with Correct Password (already set in object) ---
        print(f"\nDecrypting '{encrypted_file_path}' to '{decrypted_file_path}'...")
        try:
            crypto.decrypt_file(encrypted_file_path, decrypted_file_path, salt_file_path)
            print("Decryption successful.")

            # Verify content
            with open(dummy_file_path, 'r') as f_orig, open(decrypted_file_path, 'r') as f_dec:
                if f_orig.read() == f_dec.read():
                    print("Decrypted content matches original.")
                else:
                    print("Warning: Decrypted content does NOT match original.", file=sys.stderr)
                    print("Decrypted file content:")
                    with open(decrypted_file_path, 'r') as f_dec_print:
                         print(f_dec_print.read())

        except SystemExit:
             print("Decryption failed.", file=sys.stderr)


        # --- Test Error Handling: Decryption with wrong password/corrupt file ---
        # To test wrong password with this design, you'd need to create a *new*
        # file_cryptography object with a different password *after* encrypting,
        # then try to decrypt using the new object.
        print("\nTesting decryption failure (e.g., wrong password if using new object)...")
        print("(This test requires manually creating a new object with a different password)")
        # Example of how you would test this (requires a new object):
        # try:
        #     print("\nAttempting decryption with intentionally wrong password...")
        #     wrong_crypto = file_cryptography() # Enter a different password here
        #     wrong_crypto.decrypt_file(encrypted_file_path, "wrong_pass_test.txt", salt_file_path)
        # except SystemExit:
        #     print("Caught expected SystemExit due to incorrect password/tag.")
        #     if os.path.exists("wrong_pass_test.txt"):
        #         print("Error: Incomplete file 'wrong_pass_test.txt' was NOT cleaned up.", file=sys.stderr)
        #     else:
        #         print("Incomplete file 'wrong_pass_test.txt' was correctly cleaned up.")


        # --- Test Error Handling: File Not Found ---
        print("\nTesting encryption with non-existent input file (expecting failure)...")
        try:
            crypto.encrypt_file("non_existent_input.txt", "fail_encrypt.bin", "fail_salt.bin")
        except SystemExit:
            print("Caught expected SystemExit due to input file not found.")
            if os.path.exists("fail_encrypt.bin"):
                print("Error: fail_encrypt.bin exists unexpectedly.", file=sys.stderr)

        print("\nTesting decryption with non-existent encrypted file (expecting failure)...")
        try:
            crypto.decrypt_file("non_existent_encrypted.bin", "fail_decrypt.txt", salt_file_path)
        except SystemExit:
            print("Caught expected SystemExit due to input file not found.")
            if os.path.exists("fail_decrypt.txt"):
                print("Error: fail_decrypt.txt exists unexpectedly.", file=sys.stderr)

        print("\nTesting decryption with non-existent salt file (expecting failure)...")
        try:
            crypto.decrypt_file(encrypted_file_path, "fail_decrypt2.txt", "non_existent_salt.bin")
        except SystemExit:
            print("Caught expected SystemExit due to salt file not found.")
            if os.path.exists("fail_decrypt2.txt"):
                print("Error: fail_decrypt2.txt exists unexpectedly.", file=sys.stderr)


    finally:
        # Clean up test files
        print("\nCleaning up test files...")
        for f in [dummy_file_path, encrypted_file_path, decrypted_file_path, salt_file_path, "wrong_pass_test.txt", "fail_encrypt.bin", "fail_salt.bin", "fail_decrypt.txt", "fail_decrypt2.txt", "non_existent_salt.bin"]:
            if os.path.exists(f):
                try:
                    os.remove(f)
                    print(f"Removed {f}")
                except OSError as e:
                    print(f"Error removing {f}: {e}", file=sys.stderr)
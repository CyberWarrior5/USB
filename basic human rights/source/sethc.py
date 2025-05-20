import os
import ctypes
import winreg
from pynput import keyboard

password_input = ""
cancelled = False

def capture_password():
    global password_input, cancelled

    print("Type password for auto-login (press Enter to confirm, Ctrl to cancel):")

    def on_press(key):
        nonlocal listener
        global password_input, cancelled

        try:
            if key == keyboard.Key.enter:
                listener.stop()
            elif key == keyboard.Key.ctrl_l or key == keyboard.Key.ctrl_r:
                cancelled = True
                listener.stop()
            elif hasattr(key, 'char') and key.char:
                password_input += key.char
        except Exception:
            pass

    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()

def toggle_auto_login():
    global password_input, cancelled

    try:
        reg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
        key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        key = winreg.OpenKey(reg, key_path, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE)

        try:
            value, _ = winreg.QueryValueEx(key, "AutoAdminLogon")
        except FileNotFoundError:
            value = "0"

        if value == "1":
            winreg.SetValueEx(key, "AutoAdminLogon", 0, winreg.REG_SZ, "0")
            print("AutoAdminLogon disabled.")
        else:
            capture_password()
            if cancelled:
                print("Operation cancelled.")
                winreg.CloseKey(key)
                return
            winreg.SetValueEx(key, "AutoAdminLogon", 0, winreg.REG_SZ, "1")
            winreg.SetValueEx(key, "DefaultUserName", 0, winreg.REG_SZ, "hiddenuser")
            winreg.SetValueEx(key, "DefaultPassword", 0, winreg.REG_SZ, password_input)
            winreg.SetValueEx(key, "DefaultDomainName", 0, winreg.REG_SZ, ".")
            print("AutoAdminLogon enabled for 'hiddenuser'.")

        winreg.CloseKey(key)

    except Exception as e:
        print("Registry error:", e)

if ctypes.windll.shell32.IsUserAnAdmin():
    toggle_auto_login()
    os.system("shutdown /l")  # logout to trigger auto-login
else:
    print("Must run as SYSTEM.")

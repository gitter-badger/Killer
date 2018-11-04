import json
import os
import re
import subprocess

import fcntl

from killer.killer_base import KillerBase

BT_MAC_REGEX = re.compile("(?:[0-9a-fA-F]:?){12}")
BT_NAME_REGEX = re.compile("[0-9A-Za-z ]+(?=\s\()")
BT_CONNECTED_REGEX = re.compile("(Connected: [0-1])")
USB_ID_REGEX = re.compile("([0-9a-fA-F]{4}:[0-9a-fA-F]{4})")
CD_REGEX = re.compile("drive name:\\t\\t(\w+)")


class KillerPosix(KillerBase):
    def __init__(self, config_path: str = None, debug: bool = False):
        super().__init__(config_path, debug)

    def detect_bt(self):
        try:
            bt_command = subprocess.check_output(["bt-device", "--list"],
                                                 shell=False).decode()
        except IOError:
            if self.DEBUG:
                print("None detected\n")
            else:
                return
        else:
            if self.DEBUG:
                print("Bluetooth:")
                bt_devices = bt_command.split('\n')
                if len(bt_devices) == 3 and bt_devices[2] == '':
                    print(bt_command.split('\n')[1])
                else:
                    print(', '.join(bt_command.split('\n')[1:]))
                print()
            else:
                paired_devices = re.findall(BT_MAC_REGEX, bt_command)
                devices_names = re.findall(BT_NAME_REGEX, bt_command)
                for each in range(0, len(paired_devices)):
                    if paired_devices[each] not in json.loads(self.config['linux']['BT_PAIRED_WHITELIST']):
                        self.kill_the_system('Bluetooth Paired')
                    else:
                        connected = subprocess.check_output(["bt-device", "-i",
                                                             paired_devices[each]],
                                                             shell=False).decode()
                        connected_text = re.findall(BT_CONNECTED_REGEX, connected)
                        if connected_text[0].endswith("1") and paired_devices[each] not in json.loads(self.config['linux']['BT_CONNECTED_WHITELIST']):
                            self.kill_the_system('Bluetooth Connected MAC Disallowed')
                        elif connected_text[0].endswith("1") and each in json.loads(self.config['linux']['BT_CONNECTED_WHITELIST']):
                            if not devices_names[each] == json.loads(self.config['linux']['BT_PAIRED_WHITELIST'])[each]:
                                self.kill_the_system('Bluetooth Connected Name Mismatch')

    def detect_usb(self):
        ids = re.findall(USB_ID_REGEX, subprocess.check_output("lsusb",
                                                                shell=False).decode())
        if self.DEBUG:
            print("USB:")
            print(', '.join(ids))
            print()
        else:
            for each_device in ids:
                if each_device not in json.loads(self.config['linux']['USB_ID_WHITELIST']):
                    self.kill_the_system('USB Allowed Whitelist')
            for device in json.loads(self.config['linux']['USB_CONNECTED_WHITELIST']):
                if device not in ids:
                    self.kill_the_system('USB Connected Whitelist')

    def detect_ac(self):
        if self.DEBUG:
            ac_types = []
            for each in os.listdir("/sys/class/power_supply"):
                with open("/sys/class/power_supply/{0}/type".format(each)) as power_file:
                    the_type = power_file.readline().strip()
                    if the_type == "Mains":
                        ac_types.append(each)
            print("AC:")
            if ac_types:
                if len(ac_types) >= 2:
                    print(', '.join(ac_types))
                elif len(ac_types) == 1:
                    print(ac_types[0])
                print()
            else:
                print("None detected\n")
        else:
            with open(self.config['linux']['AC_FILE']) as ac:
                online = int(ac.readline().strip())
                if not online:
                    self.kill_the_system('AC')

    def detect_battery(self):
        if self.DEBUG:
            battery_types = []
            for each in os.listdir("/sys/class/power_supply"):
                with open("/sys/class/power_supply/{0}/type".format(each)) as power_file:
                    the_type = power_file.readline().strip()
                    if the_type == "Battery":
                        battery_types.append(each)
            print("Battery:")
            if battery_types:
                if len(battery_types) >= 2:
                    print(', '.join(battery_types))
                elif len(battery_types) == 1:
                    print(battery_types[0])
                print()
            else:
                print("None detected\n")
        else:
            try:
                with open(self.config['linux']['BATTERY_FILE']) as battery:
                    present = int(battery.readline().strip())
                    if not present:
                        self.kill_the_system('Battery')
            except FileNotFoundError:
                pass

    def detect_tray(self):
        if self.DEBUG:
            cdrom_command = subprocess.check_output(["cat", "/proc/sys/dev/cdrom/info"])
            all_cdroms = re.findall(CD_REGEX, cdrom_command)
            tray_statuses = []
            if all_cdroms:
                print('CD Trays:')
                if len(all_cdroms) >= 2:
                    print(', '.join(all_cdroms))
                elif len(all_cdroms) == 1:
                    print(all_cdroms[0])
                print('Tray Statuses:')
                for each in all_cdroms:
                    disk_tray = os.path.join('/dev/' + each)
                    fd = os.open(disk_tray, os.O_RDONLY | os.O_NONBLOCK)
                    rv = fcntl.ioctl(fd, 0x5326)
                    os.close(fd)
                    tray_statuses.append(rv)
                if len(tray_statuses) >= 2:
                    print(', '.join(tray_statuses))
                elif len(tray_statuses) == 1:
                    print(tray_statuses[0])
                print()
            else:
                print("None detected\n")
        else:
            # self.config['linux']['CDROM_DRIVE'] should be a dictionary
            disk_tray = self.config['linux']['CDROM_DRIVE']
            fd = os.open(disk_tray, os.O_RDONLY | os.O_NONBLOCK)
            rv = fcntl.ioctl(fd, 0x5326)
            os.close(fd)
            if rv != self.config['linux']['WHITELISTED_STATUS']:
                self.kill_the_system('CD Tray')

    def detect_ethernet(self):
        if self.DEBUG:
            ethernet_interfaces = []
            ethernet_statuses = []
            for each in os.listdir('/sys/class/net/'):
                if each == 'lo':
                    pass
                else:
                    wireless_dir = os.path.join('/sys/class/net/{0}/wireless'.format(each))
                    if not os.path.isdir(wireless_dir):
                        ethernet_interfaces.append(each)
                        carrier_file = os.path.join('/sys/class/net/{0}/carrier'.format(each))
                        with open(carrier_file, 'r') as ethernet_carrier:
                            connected = ethernet_carrier.readline()
                            ethernet_statuses.append(connected)
            if ethernet_interfaces:
                print('Ethernet Interface:')
                if len(ethernet_interfaces) >= 2:
                    print(', '.join(ethernet_interfaces))
                elif len(ethernet_interfaces) == 1:
                    print(ethernet_interfaces[0])
                print('Ethernet Status:')
                if len(ethernet_statuses) >= 2:
                    print(', '.join(ethernet_statuses))
                elif len(ethernet_statuses) == 1:
                    print(ethernet_statuses[0])
        else:
            # should this also be a dictionary?
            with open(self.config['linux']['ETHERNET_CONNECTED']) as ethernet:
                connected = int(ethernet.readline().strip())
            if connected != self.config['linux']['ETHERNET_WHITELIST']:
                self.kill_the_system('Ethernet')

    def kill_the_system(self, warning: str):
        super().kill_the_system(warning)
        subprocess.Popen(["/sbin/poweroff", "-f"])

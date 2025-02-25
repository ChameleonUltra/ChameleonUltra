import argparse
import os
import subprocess
import time

from platform import uname

import serial.tools.list_ports

from chameleon.chameleon_enum import (
    Command,
    Status,
)
from chameleon.chameleon_utils import (
    C0,
    CR,
)
from chameleon.commands.util import (
    ArgumentParserNoExit,
    BaseCLIUnit,
    CLITree,
    DeviceRequiredUnit,
)


hw = CLITree("hw", "Hardware-related commands", ldr=__loader__)

@hw.command('connect')
class HWConnect(BaseCLIUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Connect to chameleon by serial port'
        parser.add_argument('-p', '--port', type=str, required=False)
        return parser

    def on_exec(self, args: argparse.Namespace):
        try:
            if args.port is None:  # Chameleon auto-detect if no port is supplied
                platform_name = uname().release
                if 'Microsoft' in platform_name:
                    path = os.environ["PATH"].split(os.pathsep)
                    path.append("/mnt/c/Windows/System32/WindowsPowerShell/v1.0/")
                    powershell_path = None
                    for prefix in path:
                        fn = os.path.join(prefix, "powershell.exe")
                        if not os.path.isdir(fn) and os.access(fn, os.X_OK):
                            powershell_path = fn
                            break
                    if powershell_path:
                        process = subprocess.Popen([powershell_path,
                                                    "Get-PnPDevice -Class Ports -PresentOnly |"
                                                    " where {$_.DeviceID -like '*VID_6868&PID_8686*'} |"
                                                    " Select-Object -First 1 FriendlyName |"
                                                    " % FriendlyName |"
                                                    " select-string COM\\d+ |"
                                                    "% { $_.matches.value }"], stdout=subprocess.PIPE)
                        res = process.communicate()[0]
                        _comport = res.decode('utf-8').strip()
                        if _comport:
                            args.port = _comport.replace('COM', '/dev/ttyS')
                else:
                    # loop through all ports and find chameleon
                    for port in serial.tools.list_ports.comports():
                        if port.vid == 0x6868:
                            args.port = port.device
                            break
                if args.port is None:  # If no chameleon was found, exit
                    print("Chameleon not found, please connect the device or try connecting manually with the -p flag.")
                    return
            self.device_com.open(args.port)
            self.device_com.commands = self.cmd.get_device_capabilities()
            major, minor = self.cmd.get_app_version()
            model = ['Ultra', 'Lite'][self.cmd.get_device_model()]
            print(f" {{ Chameleon {model} connected: v{major}.{minor} }}")

        except Exception as e:
            print(f"{CR}Chameleon Connect fail: {str(e)}{C0}")
            self.device_com.close()


@hw.command('disconnect')
class HWDisconnect(BaseCLIUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Disconnect chameleon'
        return parser

    def on_exec(self, args: argparse.Namespace):
        self.device_com.close()


@hw.command('mode')
class HWMode(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Get or change device mode: tag reader or tag emulator'
        mode_group = parser.add_mutually_exclusive_group()
        mode_group.add_argument('-r', '--reader', action='store_true', help="Set reader mode")
        mode_group.add_argument('-e', '--emulator', action='store_true', help="Set emulator mode")
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.reader:
            self.cmd.set_device_reader_mode(True)
            print("Switch to {  Tag Reader  } mode successfully.")
        elif args.emulator:
            self.cmd.set_device_reader_mode(False)
            print("Switch to { Tag Emulator } mode successfully.")
        else:
            print(f"- Device Mode ( Tag {'Reader' if self.cmd.is_device_reader_mode() else 'Emulator'} )")


@hw.command('chipid')
class HWChipId(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Get device chipset ID'
        return parser

    def on_exec(self, args: argparse.Namespace):
        print(' - Device chip ID: ' + self.cmd.get_device_chip_id())


@hw.command('address')
class HWAddress(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Get device address (used with Bluetooth)'
        return parser

    def on_exec(self, args: argparse.Namespace):
        print(' - Device address: ' + self.cmd.get_device_address())


@hw.command('version')
class HWVersion(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Get current device firmware version'
        return parser

    def on_exec(self, args: argparse.Namespace):
        fw_version_tuple = self.cmd.get_app_version()
        fw_version = f'v{fw_version_tuple[0]}.{fw_version_tuple[1]}'
        git_version = self.cmd.get_git_version()
        model = ['Ultra', 'Lite'][self.cmd.get_device_model()]
        print(f' - Chameleon {model}, Version: {fw_version} ({git_version})')


@hw.command('dfu')
class HWDFU(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Restart application to bootloader/DFU mode'
        return parser

    def on_exec(self, args: argparse.Namespace):
        print("Application restarting...")
        self.cmd.enter_bootloader()
        # In theory, after the above command is executed, the dfu mode will enter, and then the USB will restart,
        # To judge whether to enter the USB successfully, we only need to judge whether the USB becomes the VID and PID
        # of the DFU device.
        # At the same time, we remember to confirm the information of the device,
        # it is the same device when it is consistent.
        print(" - Enter success @.@~")
        # let time for comm thread to send dfu cmd and close port
        time.sleep(0.1)


@hw.command('factory_reset')
class HWFactoryReset(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Wipe all slot data and custom settings and return to factory settings'
        parser.add_argument("--force", default=False, action="store_true", help="Just to be sure")
        return parser

    def on_exec(self, args: argparse.Namespace):
        if not args.force:
            print("If you are you really sure, read the command documentation to see how to proceed.")
            return
        if self.cmd.wipe_fds():
            print(" - Reset successful! Please reconnect.")
            # let time for comm thread to close port
            time.sleep(0.1)
        else:
            print(" - Reset failed!")


@hw.command('battery')
class HWBatteryInfo(DeviceRequiredUnit):
    # How much remaining battery is considered low?
    BATTERY_LOW_LEVEL = 30

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Get battery information, voltage and level'
        return parser

    def on_exec(self, args: argparse.Namespace):
        voltage, percentage = self.cmd.get_battery_info()
        print(" - Battery information:")
        print(f"   voltage    -> {voltage} mV")
        print(f"   percentage -> {percentage}%")
        if percentage < HWBatteryInfo.BATTERY_LOW_LEVEL:
            print(f"{CR}[!] Low battery, please charge.{C0}")


@hw.command('raw')
class HWRaw(DeviceRequiredUnit):

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Send raw command'
        cmd_names = sorted([c.name for c in list(Command)])
        help_str = "Command: " + ", ".join(cmd_names)
        command_group = parser.add_mutually_exclusive_group(required=True)
        command_group.add_argument('-c', '--command', type=str, metavar="COMMAND", help=help_str, choices=cmd_names)
        command_group.add_argument('-n', '--num_command', type=int, metavar="<dec>", help="Numeric command ID: <dec>")
        parser.add_argument('-d', '--data', type=str, help="Data to send", default="", metavar="<hex>")
        parser.add_argument('-t', '--timeout', type=int, help="Timeout in seconds", default=3, metavar="<dec>")
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.command is not None:
            command = Command[args.command]
        else:
            # We accept not-yet-known command ids as "hw raw" is meant for debugging
            command = args.num_command
        response = self.cmd.device.send_cmd_sync(
            command, data=bytes.fromhex(args.data), status=0x0, timeout=args.timeout)
        print(" - Received:")
        try:
            command = Command(response.cmd)
            print(f"   Command: {response.cmd} {command.name}")
        except ValueError:
            print(f"   Command: {response.cmd} (unknown)")

        status_string = f"   Status:  {response.status:#02x}"
        try:
            status = Status(response.status)
            status_string += f" {status.name}"
            status_string += f": {str(status)}"
        except ValueError:
            pass
        print(status_string)
        print(f"   Data (HEX): {response.data.hex()}")



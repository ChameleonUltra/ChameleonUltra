import argparse
import re

from chameleon.chameleon_enum import (
    AnimationMode,
    ButtonPressFunction,
    ButtonType,
)
from chameleon.chameleon_utils import (
    C0,
    CG,
    CR,
    CY,
)
from chameleon.commands.util import (
    ArgumentParserNoExit,
    CLITree,
    DeviceRequiredUnit,
)


settings = CLITree("settings", "Chameleon settings commands")


@settings.command('animation')
class HWSettingsAnimation(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Get or change current animation mode value'
        mode_names = [m.name for m in list(AnimationMode)]
        help_str = "Mode: " + ", ".join(mode_names)
        parser.add_argument('-m', '--mode', type=str, required=False,
                            help=help_str, metavar="MODE", choices=mode_names)
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.mode is not None:
            mode = AnimationMode[args.mode]
            self.cmd.set_animation_mode(mode)
            print("Animation mode change success.")
            print(f"{CY}Do not forget to store your settings in flash!{C0}")
        else:
            print(AnimationMode(self.cmd.get_animation_mode()))


@settings.command('bleclearbonds')
class HWSettingsBleClearBonds(DeviceRequiredUnit):

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Clear all BLE bindings. Warning: effect is immediate!'
        parser.add_argument("--force", default=False, action="store_true", help="Just to be sure")
        return parser

    def on_exec(self, args: argparse.Namespace):
        if not args.force:
            print("If you are you really sure, read the command documentation to see how to proceed.")
            return
        self.cmd.delete_all_ble_bonds()
        print(" - Successfully clear all bonds")


@settings.command('store')
class HWSettingsStore(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Store current settings to flash'
        return parser

    def on_exec(self, args: argparse.Namespace):
        print("Storing settings...")
        if self.cmd.save_settings():
            print(" - Store success @.@~")
        else:
            print(" - Store failed")


@settings.command('reset')
class HWSettingsReset(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Reset settings to default values'
        parser.add_argument("--force", default=False, action="store_true", help="Just to be sure")
        return parser

    def on_exec(self, args: argparse.Namespace):
        if not args.force:
            print("If you are you really sure, read the command documentation to see how to proceed.")
            return
        print("Initializing settings...")
        if self.cmd.reset_settings():
            print(" - Reset success @.@~")
        else:
            print(" - Reset failed")


@settings.command('btnpress')
class HWButtonSettingsGet(DeviceRequiredUnit):

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Get or set button press function of Button A and Button B'
        button_group = parser.add_mutually_exclusive_group()
        button_group.add_argument('-a', '-A', action='store_true', help="Button A")
        button_group.add_argument('-b', '-B', action='store_true', help="Button B")
        duration_group = parser.add_mutually_exclusive_group()
        duration_group.add_argument('-s', '--short', action='store_true', help="Short-press (default)")
        duration_group.add_argument('-l', '--long', action='store_true', help="Long-press")
        function_names = [f.name for f in list(ButtonPressFunction)]
        function_descs = [f"{f.name} ({f})" for f in list(ButtonPressFunction)]
        help_str = "Function: " + ", ".join(function_descs)
        parser.add_argument('-f', '--function', type=str, required=False,
                            help=help_str, metavar="FUNCTION", choices=function_names)
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.function is not None:
            function = ButtonPressFunction[args.function]
            if not args.a and not args.b:
                print(f"{CR}You must specify which button you want to change{C0}")
                return
            if args.a:
                button = ButtonType.A
            else:
                button = ButtonType.B
            if args.long:
                self.cmd.set_long_button_press_config(button, function)
            else:
                self.cmd.set_button_press_config(button, function)
            print(f" - Successfully set function '{function}'"
                  f" to Button {button.name} {'long-press' if args.long else 'short-press'}")
            print(f"{CY}Do not forget to store your settings in flash!{C0}")
        else:
            if args.a:
                button_list = [ButtonType.A]
            elif args.b:
                button_list = [ButtonType.B]
            else:
                button_list = list(ButtonType)
            for button in button_list:
                if not args.long:
                    resp = self.cmd.get_button_press_config(button)
                    button_fn = ButtonPressFunction(resp)
                    print(f" - {CG}{button.name} short{C0}: {button_fn}")
                if not args.short:
                    resp_long = self.cmd.get_long_button_press_config(button)
                    button_long_fn = ButtonPressFunction(resp_long)
                    print(f" - {CG}{button.name} long {C0}: {button_long_fn}")
                print("")


@settings.command('blekey')
class HWSettingsBLEKey(DeviceRequiredUnit):

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Get or set the ble connect key'
        parser.add_argument('-k', '--key', required=False, help="Ble connect key for your device")
        return parser

    def on_exec(self, args: argparse.Namespace):
        key = self.cmd.get_ble_pairing_key()
        print(" - The current key of the device(ascii): "
              f"{CG}{key}{C0}")

        if args.key is not None:
            if len(args.key) != 6:
                print(f" - {CR}The ble connect key length must be 6{C0}")
                return
            if re.match(r'[0-9]{6}', args.key):
                self.cmd.set_ble_connect_key(args.key)
                print(" - Successfully set ble connect key to :", end='')
                print(f"{CG}"
                      f" { args.key }"
                      f"{C0}"
                      )
                print(f"{CY}Do not forget to store your settings in flash!{C0}")
            else:
                print(f" - {CR}Only 6 ASCII characters from 0 to 9 are supported.{C0}")


@settings.command('blepair')
class HWBlePair(DeviceRequiredUnit):

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Show or configure BLE pairing'
        set_group = parser.add_mutually_exclusive_group()
        set_group.add_argument('-e', '--enable', action='store_true', help="Enable BLE pairing")
        set_group.add_argument('-d', '--disable', action='store_true', help="Disable BLE pairing")
        return parser

    def on_exec(self, args: argparse.Namespace):
        is_pairing_enable = self.cmd.get_ble_pairing_enable()
        if not args.enable and not args.disable:
            if is_pairing_enable:
                print(f" - BLE pairing: {CG} Enabled{C0}")
            else:
                print(f" - BLE pairing: {CR} Disabled{C0}")
        elif args.enable:
            if is_pairing_enable:
                print(f"{CY} BLE pairing is already enabled.{C0}")
                return
            self.cmd.set_ble_pairing_enable(True)
            print(f" - Successfully change ble pairing to {CG}Enabled{C0}.")
            print(f"{CY}Do not forget to store your settings in flash!{C0}")
        elif args.disable:
            if not is_pairing_enable:
                print(f"{CY} BLE pairing is already disabled.{C0}")
                return
            self.cmd.set_ble_pairing_enable(False)
            print(f" - Successfully change ble pairing to {CR}Disabled{C0}.")
            print(f"{CY}Do not forget to store your settings in flash!{C0}")

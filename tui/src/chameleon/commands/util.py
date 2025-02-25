import argparse
import re
import subprocess
import threading
import timeit

from importlib import import_module
from pathlib import Path
from pkgutil import iter_modules

from chameleon.chameleon_cmd import ChameleonCMD
from chameleon.chameleon_com import ChameleonCom
from chameleon.chameleon_enum import (
    MfcKeyType,
    SlotNumber,
    TagSpecificType,
)
from chameleon.chameleon_utils import (
    C0,
    CY,
    ArgsParserError,
    ArgumentParserNoExit,
    default_cwd,
)


class BaseCLIUnit:
    def __init__(self):
        # new a device command transfer and receiver instance(Send cmd and receive response)
        self._device_com: ChameleonCom | None = None
        self._device_cmd: ChameleonCMD | None = None

    @property
    def device_com(self) -> ChameleonCom:
        assert self._device_com is not None
        return self._device_com

    @device_com.setter
    def device_com(self, com):
        self._device_com = com
        self._device_cmd = ChameleonCMD(self._device_com)

    @property
    def cmd(self) -> ChameleonCMD:
        assert self._device_cmd is not None
        return self._device_cmd

    def args_parser(self) -> ArgumentParserNoExit:
        """
            CMD unit args.

        :return:
        """
        raise NotImplementedError("Please implement this")

    def before_exec(self, args: argparse.Namespace):
        """
            Call a function before exec cmd.

        :return: function references
        """
        return True

    def on_exec(self, args: argparse.Namespace):
        """
            Call a function on cmd match.

        :return: function references
        """
        raise NotImplementedError("Please implement this")

    def after_exec(self, args: argparse.Namespace):
        """
            Call a function after exec cmd.

        :return: function references
        """
        return True

    @staticmethod
    def sub_process(cmd, cwd=default_cwd):
        class ShadowProcess:
            def __init__(self):
                self.output = ""
                self.time_start = timeit.default_timer()
                self._process = subprocess.Popen(cmd, cwd=cwd, shell=True, stderr=subprocess.PIPE,
                                                 stdout=subprocess.PIPE)
                threading.Thread(target=self.thread_read_output).start()

            def thread_read_output(self):
                while self._process.poll() is None:
                    assert self._process.stdout is not None
                    data = self._process.stdout.read(1024)
                    if len(data) > 0:
                        self.output += data.decode(encoding="utf-8")

            def get_time_distance(self, ms=True):
                if ms:
                    return round((timeit.default_timer() - self.time_start) * 1000, 2)
                else:
                    return round(timeit.default_timer() - self.time_start, 2)

            def is_running(self):
                return self._process.poll() is None

            def is_timeout(self, timeout_ms):
                time_distance = self.get_time_distance()
                if time_distance > timeout_ms:
                    return True
                return False

            def get_output_sync(self):
                return self.output

            def get_ret_code(self):
                return self._process.poll()

            def stop_process(self):
                # noinspection PyBroadException
                try:
                    self._process.kill()
                except Exception:
                    pass

            def get_process(self):
                return self._process

            def wait_process(self):
                return self._process.wait()

        return ShadowProcess()


class DeviceRequiredUnit(BaseCLIUnit):
    """
        Make sure of device online
    """

    def before_exec(self, args: argparse.Namespace):
        ret = self.device_com.isOpen()
        if ret:
            return True
        else:
            print("Please connect to chameleon device first(use 'hw connect').")
            return False


class ReaderRequiredUnit(DeviceRequiredUnit):
    """
        Make sure of device enter to reader mode.
    """

    def before_exec(self, args: argparse.Namespace):
        if super().before_exec(args):
            ret = self.cmd.is_device_reader_mode()
            if ret:
                return True
            else:
                self.cmd.set_device_reader_mode(True)
                print("Switch to {  Tag Reader  } mode successfully.")
                return True
        return False


class SlotIndexArgsUnit(DeviceRequiredUnit):
    @staticmethod
    def add_slot_args(parser: ArgumentParserNoExit, mandatory=False):
        slot_choices = [x.value for x in SlotNumber]
        help_str = f"Slot Index: {slot_choices} Default: active slot"

        parser.add_argument('-s', "--slot", type=int, required=mandatory, help=help_str, metavar="<1-8>",
                            choices=slot_choices)
        return parser


class SlotIndexArgsAndGoUnit(SlotIndexArgsUnit):
    def before_exec(self, args: argparse.Namespace):
        if super().before_exec(args):
            self.prev_slot_num = SlotNumber.from_fw(self.cmd.get_active_slot())
            if args.slot is not None:
                self.slot_num = args.slot
                if self.slot_num != self.prev_slot_num:
                    self.cmd.set_active_slot(self.slot_num)
            else:
                self.slot_num = self.prev_slot_num
            return True
        return False

    def after_exec(self, args: argparse.Namespace):
        if self.prev_slot_num != self.slot_num:
            self.cmd.set_active_slot(self.prev_slot_num)


class SenseTypeArgsUnit(DeviceRequiredUnit):
    @staticmethod
    def add_sense_type_args(parser: ArgumentParserNoExit):
        sense_group = parser.add_mutually_exclusive_group(required=True)
        sense_group.add_argument('--hf', action='store_true', help="HF type")
        sense_group.add_argument('--lf', action='store_true', help="LF type")
        return parser


class MF1AuthArgsUnit(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.add_argument('--blk', '--block', type=int, required=True, metavar="<dec>",
                            help="The block where the key of the card is known")
        type_group = parser.add_mutually_exclusive_group()
        type_group.add_argument('-a', '-A', action='store_true', help="Known key is A key (default)")
        type_group.add_argument('-b', '-B', action='store_true', help="Known key is B key")
        parser.add_argument('-k', '--key', type=str, required=True, metavar="<hex>", help="tag sector key")
        return parser

    def get_param(self, args):
        class Param:
            def __init__(self):
                self.block = args.blk
                self.type = MfcKeyType.B if args.b else MfcKeyType.A
                key: str = args.key
                if not re.match(r"^[a-fA-F0-9]{12}$", key):
                    raise ArgsParserError("key must include 12 HEX symbols")
                self.key: bytearray = bytearray.fromhex(key)

        return Param()


class HF14AAntiCollArgsUnit(DeviceRequiredUnit):
    @staticmethod
    def add_hf14a_anticoll_args(parser: ArgumentParserNoExit):
        parser.add_argument('--uid', type=str, metavar="<hex>", help="Unique ID")
        parser.add_argument('--atqa', type=str, metavar="<hex>", help="Answer To Request")
        parser.add_argument('--sak', type=str, metavar="<hex>", help="Select AcKnowledge")
        ats_group = parser.add_mutually_exclusive_group()
        ats_group.add_argument('--ats', type=str, metavar="<hex>", help="Answer To Select")
        ats_group.add_argument('--delete-ats', action='store_true', help="Delete Answer To Select")
        return parser

    def update_hf14a_anticoll(self, args, uid, atqa, sak, ats):
        anti_coll_data_changed = False
        change_requested = False
        if args.uid is not None:
            change_requested = True
            uid_str: str = args.uid.strip()
            if re.match(r"[a-fA-F0-9]+", uid_str) is not None:
                new_uid = bytes.fromhex(uid_str)
                if len(new_uid) not in [4, 7, 10]:
                    raise Exception("UID length error")
            else:
                raise Exception("UID must be hex")
            if new_uid != uid:
                uid = new_uid
                anti_coll_data_changed = True
            else:
                print(f'{CY}Requested UID already set{C0}')
        if args.atqa is not None:
            change_requested = True
            atqa_str: str = args.atqa.strip()
            if re.match(r"[a-fA-F0-9]{4}", atqa_str) is not None:
                new_atqa = bytes.fromhex(atqa_str)
            else:
                raise Exception("ATQA must be 4-byte hex")
            if new_atqa != atqa:
                atqa = new_atqa
                anti_coll_data_changed = True
            else:
                print(f'{CY}Requested ATQA already set{C0}')
        if args.sak is not None:
            change_requested = True
            sak_str: str = args.sak.strip()
            if re.match(r"[a-fA-F0-9]{2}", sak_str) is not None:
                new_sak = bytes.fromhex(sak_str)
            else:
                raise Exception("SAK must be 2-byte hex")
            if new_sak != sak:
                sak = new_sak
                anti_coll_data_changed = True
            else:
                print(f'{CY}Requested SAK already set{C0}')
        if (args.ats is not None) or args.delete_ats:
            change_requested = True
            if args.delete_ats:
                new_ats = b''
            else:
                ats_str: str = args.ats.strip()
                if re.match(r"[a-fA-F0-9]+", ats_str) is not None:
                    new_ats = bytes.fromhex(ats_str)
                else:
                    raise Exception("ATS must be hex")
            if new_ats != ats:
                ats = new_ats
                anti_coll_data_changed = True
            else:
                print(f'{CY}Requested ATS already set{C0}')
        if anti_coll_data_changed:
            self.cmd.hf14a_set_anti_coll_data(uid, atqa, sak, ats)
        return change_requested, anti_coll_data_changed, uid, atqa, sak, ats


class MFUAuthArgsUnit(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()

        def key_parser(key: str) -> bytes:
            try:
                key = bytes.fromhex(key)
            except:
                raise ValueError("Key should be a hex string")
            
            if len(key) not in [4, 16]:
                raise ValueError("Key should either be 4 or 16 bytes long")
            elif len(key) == 16:
                raise ValueError("Ultralight-C authentication isn't supported yet")

            return key
        
        parser.add_argument(
            '-k', '--key', type=key_parser, metavar="<hex>", help="Authentication key (EV1/NTAG 4 bytes)."
        )
        parser.add_argument('-l', action='store_true', dest='swap_endian', help="Swap endianness of the key.")

        return parser

    def get_param(self, args):
        key = args.key

        if key is not None and args.swap_endian:
            key = bytearray(key)
            for i in range(len(key)):
                tmp = key[i]
                key[i] = key[len(key) - 1 - i]
            key = bytes(key)

        class Param:
            def __init__(self, key):
                self.key = key

        return Param(key)

    def on_exec(self, args: argparse.Namespace):
        raise NotImplementedError("Please implement this")


class LFEMIdArgsUnit(DeviceRequiredUnit):
    @staticmethod
    def add_card_arg(parser: ArgumentParserNoExit, required=False):
        parser.add_argument("--id", type=str, required=required, help="EM410x tag id", metavar="<hex>")
        return parser

    def before_exec(self, args: argparse.Namespace):
        if super().before_exec(args):
            if args.id is not None:
                if not re.match(r"^[a-fA-F0-9]{10}$", args.id):
                    raise ArgsParserError("ID must include 10 HEX symbols")
            return True
        return False

    def args_parser(self) -> ArgumentParserNoExit:
        raise NotImplementedError("Please implement this")

    def on_exec(self, args: argparse.Namespace):
        raise NotImplementedError("Please implement this")


class TagTypeArgsUnit(DeviceRequiredUnit):
    @staticmethod
    def add_type_args(parser: ArgumentParserNoExit):
        type_names = [t.name for t in TagSpecificType.list()]
        help_str = "Tag Type: " + ", ".join(type_names)
        parser.add_argument('-t', "--type", type=str, required=True, metavar="TAG_TYPE",
                            help=help_str, choices=type_names)
        return parser

    def args_parser(self) -> ArgumentParserNoExit:
        raise NotImplementedError()

    def on_exec(self, args: argparse.Namespace):
        raise NotImplementedError()


class CLITree:
    """
    Class holding a

    :param name: Name of the command (e.g. "set")
    :param help_text: Hint displayed for the command
    :param fullname: Full name of the command that includes previous commands (e.g. "hw settings animation")
    :param cls: A BaseCLIUnit instance handling the command
    """

    def __init__(self, name: str = "", help_text: str | None = None, fullname: str | None = None,
                 children: list["CLITree"] | None = None, cls=None, root=False, ldr=None) -> None:
        self.name = name
        self.help_text = help_text
        self.fullname = fullname if fullname else name
        self.children = children if children else []
        self.cls = cls
        self.root = root
        if self.help_text is None and not root:
            assert self.cls is not None
            parser = self.cls().args_parser()
            assert parser is not None
            self.help_text = parser.description
        if ldr:
            self.update_subcommands(ldr)

    def subgroup(self, name, help_text=None):
        """
        Create a child command group

        :param name: Name of the command group
        :param help_text: Hint displayed for the group
        """
        child = CLITree(
            name=name,
            fullname=f'{self.fullname} {name}' if not self.root else f'{name}',
            help_text=help_text)
        self.children.append(child)
        return child

    def command(self, name):
        """
        Create a child command

        :param name: Name of the command
        """
        def decorator(cls):
            self.children.append(CLITree(
                name=name,
                fullname=f'{self.fullname} {name}' if not self.root else f'{name}',
                cls=cls))
            return cls
        return decorator

    def update_subcommands(self, ldr):
        path = Path(ldr.path)
        pack = ldr.name

        for _, package_name, _ in iter_modules([str(path.parent)], f'{pack}.'):
            mod = import_module(package_name)
            attr_name = package_name.split(".")[-1]
            if (subgroup := getattr(mod, attr_name, None)) is not None:
                if self.root:
                    subgroup.fullname = subgroup.name
                else:
                    subgroup.fullname = f"{self.fullname} {subgroup.name}"
                self.children.append(subgroup)

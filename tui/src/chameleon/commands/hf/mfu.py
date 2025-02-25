import argparse
import re
import struct

from chameleon.chameleon_enum import (
    SlotNumber,
    TagSpecificType,
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
    HF14AAntiCollArgsUnit,
    MFUAuthArgsUnit,
    ReaderRequiredUnit,
    SlotIndexArgsAndGoUnit,
)


mfu = CLITree("mfu", "MIFARE Ultralight / NTAG commands")

@mfu.command('ercnt')
class HFMFUERCNT(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Read MIFARE Ultralight / NTAG counter value.'
        parser.add_argument('-c', '--counter', type=int, required=True, help="Counter index.")
        return parser

    def on_exec(self, args: argparse.Namespace):
        value, no_tearing = self.cmd.mfu_read_emu_counter_data(args.counter)
        print(f" - Value: {value:06x}")
        if no_tearing:
            print(f" - Tearing: {CG}not set{C0}")
        else:
            print(f" - Tearing: {CR}set{C0}")


@mfu.command('ewcnt')
class HFMFUEWCNT(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Read MIFARE Ultralight / NTAG counter value.'
        parser.add_argument('-c', '--counter', type=int, required=True, help="Counter index.")
        parser.add_argument('-v', '--value', type=int, required=True, help="Counter value (24-bit).")
        parser.add_argument('-t', '--reset-tearing', action='store_true', help="Reset tearing event flag.")
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.value > 0xFFFFFF:
            print(f"{CR}Counter value {args.value:#x} is too large.{C0}")
            return

        self.cmd.mfu_write_emu_counter_data(args.counter, args.value, args.reset_tearing)

        print('- Ok')


@mfu.command('rdpg')
class HFMFURDPG(MFUAuthArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = super().args_parser()
        parser.description = 'MIFARE Ultralight / NTAG read one page'
        parser.add_argument('-p', '--page', type=int, required=True, metavar="<dec>",
                            help="The page where the key will be used against")
        return parser

    def on_exec(self, args: argparse.Namespace):
        param = self.get_param(args)

        options = {
            'activate_rf_field': 0,
            'wait_response': 1,
            'append_crc': 1,
            'auto_select': 1,
            'keep_rf_field': 0,
            'check_response_crc': 1,
        }

        if param.key is not None:
            options['keep_rf_field'] = 1
            try:
                resp = self.cmd.hf14a_raw(options=options, resp_timeout_ms=200, data=struct.pack('!B', 0x1B)+param.key)

                failed_auth = len(resp) < 2
                if not failed_auth:
                    print(f" - PACK: {resp[:2].hex()}")
            except Exception:
                # failed auth may cause tags to be lost
                failed_auth = True

            options['keep_rf_field'] = 0
            options['auto_select'] = 0
        else:
            failed_auth = False

        if not failed_auth:
            resp = self.cmd.hf14a_raw(options=options, resp_timeout_ms=200, data=struct.pack('!BB', 0x30, args.page))
            print(f" - Data: {resp[:4].hex()}")
        else:
            try:
                self.cmd.hf14a_raw(options=options, resp_timeout_ms=200, data=struct.pack('!BB', 0x30, args.page))
            except:
                # we may lose the tag again here
                pass
            print(f" {CR}- Auth failed{C0}")


@mfu.command('wrpg')
class HFMFUWRPG(MFUAuthArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = super().args_parser()
        parser.description = 'MIFARE Ultralight / NTAG write one page'
        parser.add_argument('-p', '--page', type=int, required=True, metavar="<dec>",
                            help="The index of the page to write to.")
        parser.add_argument('-d', '--data', type=bytes.fromhex, required=True, metavar="<hex>",
                            help="Your page data, as a 4 byte (8 character) hex string.")
        return parser

    def on_exec(self, args: argparse.Namespace):
        param = self.get_param(args)

        data = args.data
        if len(data) != 4:
            print(f"{CR}Page data should be a 4 byte (8 character) hex string{C0}")
            return

        options = {
            'activate_rf_field': 0,
            'wait_response': 1,
            'append_crc': 1,
            'auto_select': 1,
            'keep_rf_field': 0,
            'check_response_crc': 0,
        }
        
        if param.key is not None:
            options['keep_rf_field'] = 1
            options['check_response_crc'] = 1
            try:
                resp = self.cmd.hf14a_raw(options=options, resp_timeout_ms=200, data=struct.pack('!B', 0x1B)+param.key)

                failed_auth = len(resp) < 2
                if not failed_auth:
                    print(f" - PACK: {resp[:2].hex()}")
            except Exception:
                # failed auth may cause tags to be lost
                failed_auth = True

            options['keep_rf_field'] = 0
            options['auto_select'] = 0
            options['check_response_crc'] = 0
        else:
            failed_auth = False
        
        if not failed_auth:
            resp = self.cmd.hf14a_raw(options=options, resp_timeout_ms=200, data=struct.pack('!BB', 0xA2, args.page)+data)

            if resp[0] == 0x0A:
                print(" - Ok")
            else:
                print(f"{CR}Write failed ({resp[0]:#04x}).{C0}")
        else:
            # send a command just to disable the field. use read to avoid corrupting the data
            try:
                self.cmd.hf14a_raw(options=options, resp_timeout_ms=200, data=struct.pack('!BB', 0x30, args.page))
            except:
                # we may lose the tag again here
                pass
            print(f" {CR}- Auth failed{C0}")


@mfu.command('eview')
class HFMFUEVIEW(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'MIFARE Ultralight / NTAG view emulator data'
        return parser

    def get_param(self, args):
        class Param:
            def __init__(self):
                pass

        return Param()

    def on_exec(self, args: argparse.Namespace):
        param = self.get_param(args)

        nr_pages = self.cmd.mfu_get_emu_pages_count()
        page = 0
        while page < nr_pages:
            count = min(nr_pages - page, 16)
            data = self.cmd.mfu_read_emu_page_data(page, count)
            for i in range(0, len(data), 4):
                print(f"#{page+(i>>2):02x}: {data[i:i+4].hex()}")
            page += count


@mfu.command('eload')
class HFMFUELOAD(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'MIFARE Ultralight / NTAG load emulator data'
        parser.add_argument(
            '-f', '--file', required=True, type=str, help="File to load data from."
        )
        parser.add_argument(
            '-t', '--type', type=str, required=False, help="Force writing as either raw binary or hex.", choices=['bin', 'hex']
        )
        return parser

    def get_param(self, args):
        class Param:
            def __init__(self):
                pass

        return Param()

    def on_exec(self, args: argparse.Namespace):
        file_type = args.type
        if file_type is None:
            if args.file.endswith('.eml') or args.file.endswith('.txt'):
                file_type = 'hex'
            else:
                file_type = 'bin'
        
        if file_type == 'hex':
            with open(args.file) as f:
                data = f.read()
            data = re.sub('#.*$', '', data, flags=re.MULTILINE)
            data = bytes.fromhex(data)
        else:
            with open(args.file, 'rb') as f:
                data = f.read()

        # this will throw an exception on incorrect slot type
        nr_pages = self.cmd.mfu_get_emu_pages_count()
        size = nr_pages * 4
        if len(data) > size:
            print(f"{CR}Dump file is too large for the current slot (expected {size} bytes).{C0}")
            return
        elif (len(data) % 4) > 0:
            print(f"{CR}Dump file's length is not a multiple of 4 bytes.{C0}")
            return
        elif len(data) < size:
            print(f"{CY}Dump file is smaller than the current slot's memory ({len(data)} < {size}).{C0}")
        
        nr_pages = len(data) >> 2
        page = 0
        while page < nr_pages:
            offset = page * 4
            cur_count = min(16, nr_pages - page)

            if offset >= len(data):
                page_data = bytes.fromhex("00000000") * cur_count
            else:
                page_data = data[offset:offset + 4 * cur_count]
            
            self.cmd.mfu_write_emu_page_data(page, page_data)
            page += cur_count
        
        print(" - Ok")


@mfu.command('esave')
class HFMFUESAVE(DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'MIFARE Ultralight / NTAG save emulator data'
        parser.add_argument(
            '-f', '--file', required=True, type=str, help='File to save data to.'
        )
        parser.add_argument(
            '-t', '--type', type=str, required=False, help="Force writing as either raw binary or hex.", choices=['bin', 'hex']
        )
        return parser

    def get_param(self, args):
        class Param:
            def __init__(self):
                pass

        return Param()

    def on_exec(self, args: argparse.Namespace):
        file_type = args.type
        fd = None
        save_as_eml = False

        if file_type is None:
            if args.file.endswith('.eml') or args.file.endswith('.txt'):
                file_type = 'hex'
            else:
                file_type = 'bin'

        if file_type == 'hex':
            fd = open(args.file, 'w+')
            save_as_eml = True
        else:
            fd = open(args.file, 'wb+')

        with fd:
            # this will throw an exception on incorrect slot type
            nr_pages = self.cmd.mfu_get_emu_pages_count()

            fd.truncate(0)
            
            # write version and signature as comments if saving as .eml
            if save_as_eml:
                try:
                    version = self.cmd.mf0_ntag_get_version_data()

                    fd.write(f"# Version: {version.hex()}\n")
                except:
                    pass # slot does not have version data
                
                try:
                    signature = self.cmd.mf0_ntag_get_signature_data()

                    if signature != b"\x00" * 32:
                        fd.write(f"# Signature: {signature.hex()}\n")
                except:
                    pass # slot does not have signature data
            
            page = 0
            while page < nr_pages:
                cur_count = min(32, nr_pages - page)
                
                data = self.cmd.mfu_read_emu_page_data(page, cur_count)
                if save_as_eml:
                    for i in range(0, len(data), 4):
                        fd.write(data[i:i+4].hex() + "\n")
                else:
                    fd.write(data)
                
                page += cur_count
        
        print(" - Ok")


@mfu.command('rcnt')
class HFMFURCNT(MFUAuthArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = super().args_parser()
        parser.description = 'MIFARE Ultralight / NTAG read counter'
        parser.add_argument('-c', '--counter', type=int, required=True, metavar="<dec>",
                            help="Index of the counter to read (always 0 for NTAG, 0-2 for Ultralight EV1).")
        return parser

    def on_exec(self, args: argparse.Namespace):
        param = self.get_param(args)

        options = {
            'activate_rf_field': 0,
            'wait_response': 1,
            'append_crc': 1,
            'auto_select': 1,
            'keep_rf_field': 0,
            'check_response_crc': 1,
        }
        
        if param.key is not None:
            options['keep_rf_field'] = 1
            try:
                resp = self.cmd.hf14a_raw(options=options, resp_timeout_ms=200, data=struct.pack('!B', 0x1B)+param.key)

                failed_auth = len(resp) < 2
                if not failed_auth:
                    print(f" - PACK: {resp[:2].hex()}")
            except Exception:
                # failed auth may cause tags to be lost
                failed_auth = True

            options['keep_rf_field'] = 0
            options['auto_select'] = 0
        else:
            failed_auth = False
        
        if not failed_auth:
            resp = self.cmd.hf14a_raw(options=options, resp_timeout_ms=200, data=struct.pack('!BB', 0x39, args.counter))
            print(f" - Data: {resp[:3].hex()}")
        else:
            try:
                self.cmd.hf14a_raw(options=options, resp_timeout_ms=200, data=struct.pack('!BB', 0x39, args.counter))
            except:
                # we may lose the tag again here
                pass
            print(f" {CR}- Auth failed{C0}")


@mfu.command('dump')
class HFMFUDUMP(MFUAuthArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = super().args_parser()
        parser.description = 'MIFARE Ultralight dump pages'
        parser.add_argument('-p', '--page', type=int, required=False, metavar="<dec>", default=0,
                            help="Manually set number of pages to dump")
        parser.add_argument('-q', '--qty', type=int, required=False, metavar="<dec>",
                            help="Manually set number of pages to dump")
        parser.add_argument('-f', '--file', type=str, required=False, default="",
                            help="Specify a filename for dump file")
        parser.add_argument('-t', '--type', type=str, required=False, choices=['bin', 'hex'], 
                            help="Force writing as either raw binary or hex.")
        return parser
    
    def do_dump(self, args: argparse.Namespace, param, fd, save_as_eml):
        if args.qty is not None:
            stop_page = min(args.page + args.qty, 256)
        else:
            stop_page = None
        
        tags = self.cmd.hf14a_scan()
        if len(tags) > 1:
            print(f'- {CR}Collision detected, leave only one tag.{C0}')
            return
        elif len(tags) == 0:
            print(f'- {CR}No tag detected.{C0}')
            return
        elif tags[0]['atqa'] != b'\x44\x00' or tags[0]['sak'] != b'\x00':
            print(f'- {CR}Tag is not Mifare Ultralight compatible (ATQA {tags[0]["atqa"].hex()} SAK {tags[0]["sak"].hex()}).{C0}')
            return
        
        options = {
            'activate_rf_field': 0,
            'wait_response': 1,
            'append_crc': 1,
            'auto_select': 1,
            'keep_rf_field': 1,
            'check_response_crc': 1,
        }
        
        # if stop page isn't set manually, try autodetection
        if stop_page is None:
            tag_name = None

            # first try sending the GET_VERSION command
            try:
                version = self.cmd.hf14a_raw(options=options, resp_timeout_ms=100, data=struct.pack('!B', 0x60))
                if len(version) == 0:
                    version = None
            except:
                version = None
            
            # try sending AUTHENTICATE command and observe the result
            try:
                supports_auth = len(self.cmd.hf14a_raw(options=options, resp_timeout_ms=100, data=struct.pack('!B', 0x1A))) != 0
            except:
                supports_auth = False
            
            if version is not None and not supports_auth:
                # either ULEV1 or NTAG
                assert len(version) == 8

                is_mikron_ulev1 = version[1] == 0x34 and version[2] == 0x21
                if (version[2] == 3 or is_mikron_ulev1) and version[4] == 1 and version[5] == 0:
                    # Ultralight EV1 V0
                    size_map = {
                        0x0B: ('Mifare Ultralight EV1 48b', 20),
                        0x0E: ('Mifare Ultralight EV1 128b', 41),
                    }
                elif version[2] == 4 and version[4] == 1 and version[5] == 0:
                    # NTAG 210/212/213/215/216 V0
                    size_map = {
                        0x0B: ('NTAG 210', 20),
                        0x0E: ('NTAG 212', 41),
                        0x0F: ('NTAG 213', 45),
                        0x11: ('NTAG 215', 135),
                        0x13: ('NTAG 216', 231),
                    }
                else:
                    size_map = {}
                
                if version[6] in size_map:
                    tag_name, stop_page = size_map[version[6]]
            elif version is None and supports_auth:
                # Ultralight C
                tag_name = 'Mifare Ultralight C'
                stop_page = 48
            elif version is None and not supports_auth:
                try:
                    # Invalid command returning a NAK means that's some old type of NTAG.
                    self.cmd.hf14a_raw(options=options, resp_timeout_ms=100, data=struct.pack('!B', 0xFF))

                    print(f' - {CY}Tag is likely NTAG 20x, reading until first error.{C0}')
                    stop_page = 256
                except:
                    # Regular Ultralight
                    tag_name = 'Mifare Ultralight'
                    stop_page = 16
            else:
                # This is probably Ultralight AES, but we don't support this one yet.
                pass
            
            if tag_name is not None:
                print(f' - Detected tag type as {tag_name}.')

            if stop_page is None:
                print(f' - {CY}Couldn\'t autodetect the expected card size, reading until first error.{C0}')
                stop_page = 256
        
        needs_stop = False

        if param.key is not None:
            try:
                resp = self.cmd.hf14a_raw(options=options, resp_timeout_ms=200, data=struct.pack('!B', 0x1B)+param.key)

                needs_stop = len(resp) < 2
                if not needs_stop:
                    print(f" - PACK: {resp[:2].hex()}")
            except Exception:
                # failed auth may cause tags to be lost
                needs_stop = True

            options['auto_select'] = 0
        
        # this handles auth failure
        if needs_stop:
            print(f" - {CR}Auth failed{C0}")
            if fd is not None:
                fd.close()
                fd = None

        for i in range(args.page, stop_page):
            # this could be done once in theory but the command would need to be optimized properly
            if param.key is not None and not needs_stop:
                resp = self.cmd.hf14a_raw(options=options, resp_timeout_ms=200, data=struct.pack('!B', 0x1B)+param.key)
                options['auto_select'] = 0  # prevent resets
                pack = resp[:2].hex()
            
            # disable the rf field after the last command
            if i == (stop_page - 1) or needs_stop:
                options['keep_rf_field'] = 0

            try:
                resp = self.cmd.hf14a_raw(options=options, resp_timeout_ms=200, data=struct.pack('!BB', 0x30, i))
            except:
                # probably lost tag, but we still need to disable rf field
                resp = None

            if needs_stop:
                # break if this command was sent just to disable RF field
                break
            elif resp is None or len(resp) == 0:
                # we need to disable RF field if we reached the last valid page so send one more read command
                needs_stop = True
                continue

            # after the read we are sure we no longer need to select again
            options['auto_select'] = 0

            # TODO: can be optimized as we get 4 pages at once but beware of wrapping
            # in case of end of memory or LOCK on ULC and no key provided
            data = resp[:4]
            print(f" - Page {i:2}: {data.hex()}")
            if fd is not None:
                if save_as_eml:
                    fd.write(data.hex()+'\n')
                else:
                    fd.write(data)
        
        if needs_stop and stop_page != 256:
            print(f' - {CY}Dump is shorter than expected.{C0}')
        if args.file != '':
            print(f" - {CG}Dump written in {args.file}.{C0}")

    def on_exec(self, args: argparse.Namespace):
        param = self.get_param(args)

        file_type = args.type
        fd = None
        save_as_eml = False

        if args.file != '':
            if file_type is None:
                if args.file.endswith('.eml') or args.file.endswith('.txt'):
                    file_type = 'hex'
                else:
                    file_type = 'bin'

            if file_type == 'hex':
                fd = open(args.file, 'w+')
                save_as_eml = True
            else:
                fd = open(args.file, 'wb+')

        if fd is not None:
            with fd:
                fd.truncate(0)
                self.do_dump(args, param, fd, save_as_eml)
        else:
            self.do_dump(args, param, fd, save_as_eml)


@mfu.command('version')
class HFMFUVERSION(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Request MIFARE Ultralight / NTAG version data.'
        return parser

    def on_exec(self, args: argparse.Namespace):
        options = {
            'activate_rf_field': 0,
            'wait_response': 1,
            'append_crc': 1,
            'auto_select': 1,
            'keep_rf_field': 0,
            'check_response_crc': 1,
        }

        resp = self.cmd.hf14a_raw(options=options, resp_timeout_ms=200, data=struct.pack('!B', 0x60))
        print(f" - Data: {resp[:8].hex()}")


@mfu.command('signature')
class HFMFUSIGNATURE(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Request MIFARE Ultralight / NTAG ECC signature data.'
        return parser

    def on_exec(self, args: argparse.Namespace):
        options = {
            'activate_rf_field': 0,
            'wait_response': 1,
            'append_crc': 1,
            'auto_select': 1,
            'keep_rf_field': 0,
            'check_response_crc': 1,
        }

        resp = self.cmd.hf14a_raw(options=options, resp_timeout_ms=200, data=struct.pack('!BB', 0x3C, 0x00))
        print(f" - Data: {resp[:32].hex()}")


@mfu.command('econfig')
class HFMFUEConfig(SlotIndexArgsAndGoUnit, HF14AAntiCollArgsUnit, DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Settings of Mifare Ultralight / NTAG emulator'
        self.add_slot_args(parser)
        self.add_hf14a_anticoll_args(parser)
        uid_magic_group = parser.add_mutually_exclusive_group()
        uid_magic_group.add_argument('--enable-uid-magic', action='store_true', help="Enable UID magic mode")
        uid_magic_group.add_argument('--disable-uid-magic', action='store_true', help="Disable UID magic mode")
        parser.add_argument('--set-version', type=bytes.fromhex, help="Set data to be returned by the GET_VERSION command.")
        parser.add_argument('--set-signature', type=bytes.fromhex, help="Set data to be returned by the READ_SIG command.")
        parser.add_argument('--reset-auth-cnt', action='store_true', help="Resets the counter of unsuccessful authentication attempts.")
        return parser

    def on_exec(self, args: argparse.Namespace):
        aux_data_changed = False
        aux_data_change_requested = False
        
        if args.set_version is not None:
            aux_data_change_requested = True
            aux_data_changed = True

            if len(args.set_version) != 8:
                print(f"{CR}Version data should be 8 bytes long.{C0}")
                return
            
            try:
                self.cmd.mf0_ntag_set_version_data(args.set_version)
            except:
                print(f"{CR}Tag type does not support GET_VERSION command.{C0}")
                return

        if args.set_signature is not None:
            aux_data_change_requested = True
            aux_data_changed = True

            if len(args.set_signature) != 32:
                print(f"{CR}Signature data should be 32 bytes long.{C0}")
                return
            
            try:
                self.cmd.mf0_ntag_set_signature_data(args.set_signature)
            except:
                print(f"{CR}Tag type does not support READ_SIG command.{C0}")
                return
        
        if args.reset_auth_cnt:
            aux_data_change_requested = True
            old_value = self.cmd.mfu_reset_auth_cnt()
            if old_value != 0:
                aux_data_changed = True
                print(f"- Unsuccessful auth counter has been reset from {old_value} to 0.")

        # collect current settings
        anti_coll_data = self.cmd.hf14a_get_anti_coll_data()
        if len(anti_coll_data) == 0:
            print(f"{CR}Slot {self.slot_num} does not contain any HF 14A config{C0}")
            return
        uid = anti_coll_data['uid']
        atqa = anti_coll_data['atqa']
        sak = anti_coll_data['sak']
        ats = anti_coll_data['ats']
        slotinfo = self.cmd.get_slot_info()
        fwslot = SlotNumber.to_fw(self.slot_num)
        hf_tag_type = TagSpecificType(slotinfo[fwslot]['hf'])
        if hf_tag_type not in [
            TagSpecificType.MF0ICU1,
            TagSpecificType.MF0ICU2,
            TagSpecificType.MF0UL11,
            TagSpecificType.MF0UL21,
            TagSpecificType.NTAG_210,
            TagSpecificType.NTAG_212,
            TagSpecificType.NTAG_213,
            TagSpecificType.NTAG_215,
            TagSpecificType.NTAG_216,
        ]:
            print(f"{CR}Slot {self.slot_num} not configured as MIFARE Ultralight / NTAG{C0}")
            return
        change_requested, change_done, uid, atqa, sak, ats = self.update_hf14a_anticoll(args, uid, atqa, sak, ats)

        if args.enable_uid_magic:
            change_requested = True
            self.cmd.mf0_ntag_set_uid_magic_mode(True)
            magic_mode = True
        elif args.disable_uid_magic:
            change_requested = True
            self.cmd.mf0_ntag_set_uid_magic_mode(False)
            magic_mode = False
        else:
            magic_mode = self.cmd.mf0_ntag_get_uid_magic_mode()

        if change_done or aux_data_changed:
            print(' - MFU/NTAG Emulator settings updated')
        if not (change_requested or aux_data_change_requested):
            print(f'- {"Type:":40}{CY}{hf_tag_type}{C0}')
            print(f'- {"UID:":40}{CY}{uid.hex().upper()}{C0}')
            print(f'- {"ATQA:":40}{CY}{atqa.hex().upper()} '
                  f'(0x{int.from_bytes(atqa, byteorder="little"):04x}){C0}')
            print(f'- {"SAK:":40}{CY}{sak.hex().upper()}{C0}')
            if len(ats) > 0:
                print(f'- {"ATS:":40}{CY}{ats.hex().upper()}{C0}')
            if magic_mode: 
                print(f'- {"UID Magic:":40}{CY}enabled{C0}')
            else:
                print(f'- {"UID Magic:":40}{CY}disabled{C0}')
            
            try:
                version = self.cmd.mf0_ntag_get_version_data()
                print(f'- {"Version:":40}{CY}{version.hex().upper()}{C0}')
            except:
                pass
            
            try:
                signature = self.cmd.mf0_ntag_get_signature_data()
                print(f'- {"Signature:":40}{CY}{signature.hex().upper()}{C0}')
            except:
                pass

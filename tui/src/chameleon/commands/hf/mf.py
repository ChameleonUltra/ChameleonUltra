import argparse
import binascii
import re
import struct
import subprocess
import sys
import time

from datetime import datetime
from multiprocessing import Pool, cpu_count

from chameleon.chameleon_enum import (
    MfcKeyType,
    MfcValueBlockOperator,
    MifareClassicDarksideStatus,
    MifareClassicWriteMode,
    SlotNumber,
    Status,
    TagSpecificType,
)
from chameleon.chameleon_utils import (
    C0,
    CG,
    CR,
    CY,
    ArgsParserError,
    UnexpectedResponseError,
    color_string,
    default_cwd,
    print_mem_dump,
)
from chameleon.commands.util import (
    ArgumentParserNoExit,
    CLITree,
    DeviceRequiredUnit,
    HF14AAntiCollArgsUnit,
    MF1AuthArgsUnit,
    ReaderRequiredUnit,
    SlotIndexArgsAndGoUnit,
)


mf = CLITree("mf", "MIFARE Classic commands")

_KEY = re.compile("[a-fA-F0-9]{12}", flags=re.MULTILINE)


def _run_mfkey32v2(items):
    output_str = subprocess.run(
        [
            default_cwd / ("mfkey32v2.exe" if sys.platform == "win32" else "mfkey32v2"),
            items[0]["uid"],
            items[0]["nt"],
            items[0]["nr"],
            items[0]["ar"],
            items[1]["nt"],
            items[1]["nr"],
            items[1]["ar"],
        ],
        capture_output=True,
        check=True,
        encoding="ascii",
    ).stdout
    sea_obj = _KEY.search(output_str)
    if sea_obj is not None:
        return sea_obj[0], items
    return None


class ItemGenerator:
    def __init__(self, rs, i=0, j=1):
        self.rs = rs
        self.i = 0
        self.j = 1
        self.found = set()
        self.keys = set()

    def __iter__(self):
        return self

    def __next__(self):
        try:
            item_i = self.rs[self.i]
        except IndexError:
            raise StopIteration
        if self.key_from_item(item_i) in self.found:
            self.i += 1
            self.j = self.i + 1
            return next(self)
        try:
            item_j = self.rs[self.j]
        except IndexError:
            self.i += 1
            self.j = self.i + 1
            return next(self)
        self.j += 1
        if self.key_from_item(item_j) in self.found:
            return next(self)
        return item_i, item_j

    @staticmethod
    def key_from_item(item):
        return "{uid}-{nt}-{nr}-{ar}".format(**item)

    def key_found(self, key, items):
        self.keys.add(key)
        for item in items:
            try:
                if item == self.rs[self.i]:
                    self.i += 1
                    self.j = self.i + 1
            except IndexError:
                break
        self.found.update(self.key_from_item(item) for item in items)


@mf.command('nested')
class HFMFNested(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Mifare Classic nested recover key'
        parser.add_argument('--blk', '--known-block', type=int, required=True, metavar="<dec>",
                            help="Known key block number")
        srctype_group = parser.add_mutually_exclusive_group()
        srctype_group.add_argument('-a', '-A', action='store_true', help="Known key is A key (default)")
        srctype_group.add_argument('-b', '-B', action='store_true', help="Known key is B key")
        parser.add_argument('-k', '--key', type=str, required=True, metavar="<hex>", help="Known key")
        # tblk required because only single block mode is supported for now
        parser.add_argument('--tblk', '--target-block', type=int, required=True, metavar="<dec>",
                            help="Target key block number")
        dsttype_group = parser.add_mutually_exclusive_group()
        dsttype_group.add_argument('--ta', '--tA', action='store_true', help="Target A key (default)")
        dsttype_group.add_argument('--tb', '--tB', action='store_true', help="Target B key")
        return parser

    def from_nt_level_code_to_str(self, nt_level):
        if nt_level == 0:
            return 'StaticNested'
        if nt_level == 1:
            return 'Nested'
        if nt_level == 2:
            return 'HardNested'

    def recover_a_key(self, block_known, type_known, key_known, block_target, type_target) -> str | None:
        """
            recover a key from key known.

        :param block_known:
        :param type_known:
        :param key_known:
        :param block_target:
        :param type_target:
        :return:
        """
        # check nt level, we can run static or nested auto...
        nt_level = self.cmd.mf1_detect_prng()
        print(f" - NT vulnerable: {color_string((CY, self.from_nt_level_code_to_str(nt_level)))}")
        if nt_level == 2:
            print(" [!] HardNested has not been implemented yet.")
            return None

        # acquire
        if nt_level == 0:  # It's a staticnested tag?
            nt_uid_obj = self.cmd.mf1_static_nested_acquire(
                block_known, type_known, key_known, block_target, type_target)
            cmd_param = f"{nt_uid_obj['uid']} {int(type_target)}"
            for nt_item in nt_uid_obj['nts']:
                cmd_param += f" {nt_item['nt']} {nt_item['nt_enc']}"
            tool_name = "staticnested"
        else:
            dist_obj = self.cmd.mf1_detect_nt_dist(block_known, type_known, key_known)
            nt_obj = self.cmd.mf1_nested_acquire(block_known, type_known, key_known, block_target, type_target)
            # create cmd
            cmd_param = f"{dist_obj['uid']} {dist_obj['dist']}"
            for nt_item in nt_obj:
                cmd_param += f" {nt_item['nt']} {nt_item['nt_enc']} {nt_item['par']}"
            tool_name = "nested"

        # Cross-platform compatibility
        if sys.platform == "win32":
            cmd_recover = f"{tool_name}.exe {cmd_param}"
        else:
            cmd_recover = f"./{tool_name} {cmd_param}"

        print(f"   Executing {cmd_recover}")
        # start a decrypt process
        process = self.sub_process(cmd_recover)

        # wait end
        while process.is_running():
            msg = f"   [ Time elapsed {process.get_time_distance()/1000:#.1f}s ]\r"
            print(msg, end="")
            time.sleep(0.1)
        # clear \r
        print()

        if process.get_ret_code() == 0:
            output_str = process.get_output_sync()
            key_list = []
            for line in output_str.split('\n'):
                sea_obj = re.search(r"([a-fA-F0-9]{12})", line)
                if sea_obj is not None:
                    key_list.append(sea_obj[1])
            # Here you have to verify the password first, and then get the one that is successfully verified
            # If there is no verified password, it means that the recovery failed, you can try again
            print(f" - [{len(key_list)} candidate key(s) found ]")
            for key in key_list:
                key_bytes = bytearray.fromhex(key)
                if self.cmd.mf1_auth_one_key_block(block_target, type_target, key_bytes):
                    return key
        else:
            # No keys recover, and no errors.
            return None

    def on_exec(self, args: argparse.Namespace):
        block_known = args.blk
        # default to A
        type_known = MfcKeyType.B if args.b else MfcKeyType.A
        key_known: str = args.key
        if not re.match(r"^[a-fA-F0-9]{12}$", key_known):
            print("key must include 12 HEX symbols")
            return
        key_known_bytes = bytes.fromhex(key_known)
        block_target = args.tblk
        # default to A
        type_target = MfcKeyType.B if args.tb else MfcKeyType.A
        if block_known == block_target and type_known == type_target:
            print(color_string((CR, "Target key already known")))
            return
        print(f" - {color_string((C0, 'Nested recover one key running...'))}")
        key = self.recover_a_key(block_known, type_known, key_known_bytes, block_target, type_target)
        if key is None:
            print(color_string((CY, "No key found, you can retry.")))
        else:
            print(f" - Block {block_target} Type {type_target.name} Key Found: {color_string((CG, key))}")
        return


@mf.command('darkside')
class HFMFDarkside(ReaderRequiredUnit):
    def __init__(self):
        super().__init__()
        self.darkside_list = []

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Mifare Classic darkside recover key'
        return parser

    def recover_key(self, block_target, type_target):
        """
            Execute darkside acquisition and decryption.

        :param block_target:
        :param type_target:
        :return:
        """
        first_recover = True
        retry_count = 0
        while retry_count < 0xFF:
            darkside_resp = self.cmd.mf1_darkside_acquire(block_target, type_target, first_recover, 30)
            first_recover = False  # not first run.
            if darkside_resp[0] != MifareClassicDarksideStatus.OK:
                print(f"Darkside error: {MifareClassicDarksideStatus(darkside_resp[0])}")
                break
            darkside_obj = darkside_resp[1]

            if darkside_obj['par'] != 0:  # NXP tag workaround.
                self.darkside_list.clear()

            self.darkside_list.append(darkside_obj)
            recover_params = f"{darkside_obj['uid']}"
            for darkside_item in self.darkside_list:
                recover_params += f" {darkside_item['nt1']} {darkside_item['ks1']} {darkside_item['par']}"
                recover_params += f" {darkside_item['nr']} {darkside_item['ar']}"
            if sys.platform == "win32":
                cmd_recover = f"darkside.exe {recover_params}"
            else:
                cmd_recover = f"./darkside {recover_params}"
            # subprocess.run(cmd_recover, cwd=os.path.abspath("../bin/"), shell=True)
            # print(f"   Executing {cmd_recover}")
            # start a decrypt process
            process = self.sub_process(cmd_recover)
            # wait end
            process.wait_process()
            # get output
            output_str = process.get_output_sync()
            if 'key not found' in output_str:
                print(f" - No key found, retrying({retry_count})...")
                retry_count += 1
                continue  # retry
            else:
                key_list = []
                for line in output_str.split('\n'):
                    sea_obj = re.search(r"([a-fA-F0-9]{12})", line)
                    if sea_obj is not None:
                        key_list.append(sea_obj[1])
                # auth key
                for key in key_list:
                    key_bytes = bytearray.fromhex(key)
                    if self.cmd.mf1_auth_one_key_block(block_target, type_target, key_bytes):
                        return key
        return None

    def on_exec(self, args: argparse.Namespace):
        key = self.recover_key(0x03, MfcKeyType.A)
        if key is not None:
            print(f" - Key Found: {key}")
        else:
            print(" - Key recover fail.")
        return


@mf.command('fchk')
class HFMFFCHK(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()

        mifare_type_group = parser.add_mutually_exclusive_group()
        mifare_type_group.add_argument('--mini', help='MIFARE Classic Mini / S20', action='store_const', dest='maxSectors', const=5)
        mifare_type_group.add_argument('--1k', help='MIFARE Classic 1k / S50 (default)', action='store_const', dest='maxSectors', const=16)
        mifare_type_group.add_argument('--2k', help='MIFARE Classic/Plus 2k', action='store_const', dest='maxSectors', const=32)
        mifare_type_group.add_argument('--4k', help='MIFARE Classic 4k / S70', action='store_const', dest='maxSectors', const=40)

        parser.add_argument(dest='keys', help='Key (as hex[12] format)', metavar='<hex>', type=str, nargs='*')
        parser.add_argument('--key', dest='import_key', type=argparse.FileType('rb'), help='Read keys from .key format file')
        parser.add_argument('--dic', dest='import_dic', type=argparse.FileType('r', encoding='utf8'), help='Read keys from .dic format file')

        parser.add_argument('--export-key', type=argparse.FileType('wb'), help=f'Export result as .key format, file will be {color_string((CR, "OVERWRITTEN"))} if exists')
        parser.add_argument('--export-dic', type=argparse.FileType('w', encoding='utf8'), help=f'Export result as .dic format, file will be {color_string((CR, "OVERWRITTEN"))} if exists')

        parser.add_argument('-m', '--mask', help='Which sectorKey to be skip, 1 bit per sectorKey. `0b1` represent to skip to check. (in hex[20] format)', type=str, default='00000000000000000000', metavar='<hex>')

        parser.set_defaults(maxSectors=16)
        return parser
    
    def check_keys(self, mask: bytearray, keys: list[bytes], chunkSize=20):
        sectorKeys = dict()

        for i in range(0, len(keys), chunkSize):
            # print("mask = {}".format(mask.hex(sep=' ', bytes_per_sep=1)))
            chunkKeys = keys[i:i+chunkSize]
            print(f' - progress of checking keys... {color_string((CY, i))} / {len(keys)} ({color_string((CY, f"{100 * i / len(keys):.1f}"))} %)')
            resp = self.cmd.mf1_check_keys_of_sectors(mask, chunkKeys)
            # print(resp)

            if resp["status"] != Status.HF_TAG_OK:
                print(f' - check interrupted, reason: {color_string((CR, Status(resp["status"])))}')
                break
            elif 'sectorKeys' not in resp:
                print(f' - check interrupted, reason: {color_string((CG, "All sectorKey is found or masked"))}')
                break

            for j in range(10):
                mask[j] |= resp['found'][j]
            sectorKeys.update(resp['sectorKeys'])

        return sectorKeys

    def on_exec(self, args: argparse.Namespace):
        # print(args)

        keys = set()

        # keys from args
        for key in args.keys:
            if not re.match(r'^[a-fA-F0-9]{12}$', key):
                print(f' - {color_string((CR, "Key should in hex[12] format, invalid key is ignored"))}, key = "{key}"')
                continue
            keys.add(bytes.fromhex(key))

        # read keys from key format file
        if args.import_key is not None:
            if not load_key_file(args.import_key, keys):
                return

        if args.import_dic is not None:
            for key in args.import_dic.readlines():
                if key.startswith("#"): # ignore comments
                    pass
                elif key.isspace(): # ignore empty lines
                    pass
                elif re.match(r'^[a-fA-F0-9]{12}$', key): # take only this key format
                    keys.add(bytes.fromhex(key))
                else: # in case of another format, a conversion is needed
                    print(f' - {color_string((CR, "Key should in hex[12] format, invalid key is ignored"))}, key = "{key}"')
                continue

        if len(keys) == 0:
            print(f' - {color_string((CR, "No keys"))}')
            return

        print(f" - loaded {color_string((CG, len(keys)))} keys")

        # mask
        if not re.match(r'^[a-fA-F0-9]{1,20}$', args.mask):
            print(f' - {color_string((CR, "mask should in hex[20] format"))}, mask = "{args.mask}"')
            return
        mask = bytearray.fromhex(f'{args.mask:0<20}')
        for i in range(args.maxSectors, 40):
            mask[i // 4] |= 3 << (6 - i % 4 * 2)

        # check keys
        startedAt = datetime.now()
        sectorKeys = self.check_keys(mask, list(keys))
        endedAt = datetime.now()
        duration = endedAt - startedAt
        print(f" - elapsed time: {color_string((CY, f'{duration.total_seconds():.3f}s'))}")

        if args.export_key is not None:
            unknownkey = bytes(6)
            for sectorNo in range(args.maxSectors):
                args.export_key.write(sectorKeys.get(2 * sectorNo, unknownkey))
                args.export_key.write(sectorKeys.get(2 * sectorNo + 1, unknownkey))
            print(f" - result exported to: {color_string((CG, args.export_key.name))} (as .key format)")

        if args.export_dic is not None:
            uniq_result = set(sectorKeys.values())
            for key in uniq_result:
                args.export_dic.write(key.hex().upper() + '\n')
            print(f" - result exported to: {color_string((CG, args.export_dic.name))} (as .dic format)")

        # print sectorKeys
        print(f"\n - {color_string((CG, 'result of key checking:'))}\n")
        print("-----+-----+--------------+---+--------------+----")
        print(" Sec | Blk | key A        |res| key B        |res ")
        print("-----+-----+--------------+---+--------------+----")
        for sectorNo in range(args.maxSectors):
            blk = (sectorNo * 4 + 3) if sectorNo < 32 else (sectorNo * 16 - 369)
            keyA = sectorKeys.get(2 * sectorNo, None)
            if keyA:
                keyA = f"{color_string((CG, keyA.hex().upper()))} | {color_string((CG, '1'))}"
            else:
                keyA = f"{color_string((CR, '------------'))} | {color_string((CR, '0'))}"
            keyB = sectorKeys.get(2 * sectorNo + 1, None)
            if keyB:
                keyB = f"{color_string((CG, keyB.hex().upper()))} | {color_string((CG, '1'))}"
            else:
                keyB = f"{color_string((CR, '------------'))} | {color_string((CR, '0'))}"
            print(f" {color_string((CY, f'{sectorNo:03d}'))} | {blk:03d} | {keyA} | {keyB} ")
        print("-----+-----+--------------+---+--------------+----")
        print(f"( {color_string((CR, '0'))}: Failed, {color_string((CG, '1'))}: Success )\n\n")


@mf.command('rdbl')
class HFMFRDBL(MF1AuthArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = super().args_parser()
        parser.description = 'Mifare Classic read one block'
        return parser

    def on_exec(self, args: argparse.Namespace):
        param = self.get_param(args)
        resp = self.cmd.mf1_read_one_block(param.block, param.type, param.key)
        print(f" - Data: {resp.hex()}")


@mf.command('wrbl')
class HFMFWRBL(MF1AuthArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = super().args_parser()
        parser.description = 'Mifare Classic write one block'
        parser.add_argument('-d', '--data', type=str, required=True, metavar="<hex>",
                            help="Your block data, as hex string.")
        return parser

    def on_exec(self, args: argparse.Namespace):
        param = self.get_param(args)
        if not re.match(r"^[a-fA-F0-9]{32}$", args.data):
            raise ArgsParserError("Data must include 32 HEX symbols")
        data = bytearray.fromhex(args.data)
        resp = self.cmd.mf1_write_one_block(param.block, param.type, param.key, data)
        if resp:
            print(f" - {color_string((CG, 'Write done.'))}")
        else:
            print(f" - {color_string((CR, 'Write fail.'))}")

@mf.command('view')
class HFMFView(MF1AuthArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Display content from tag memory or dump file'
        mifare_type_group = parser.add_mutually_exclusive_group()
        mifare_type_group.add_argument('--mini', help='MIFARE Classic Mini / S20', action='store_const', dest='maxSectors', const=5)
        mifare_type_group.add_argument('--1k', help='MIFARE Classic 1k / S50 (default)', action='store_const', dest='maxSectors', const=16)
        mifare_type_group.add_argument('--2k', help='MIFARE Classic/Plus 2k', action='store_const', dest='maxSectors', const=32)
        mifare_type_group.add_argument('--4k', help='MIFARE Classic 4k / S70', action='store_const', dest='maxSectors', const=40)
        parser.add_argument('-d', '--dump-file', required=False, type=argparse.FileType("rb"), help="Dump file to read")
        parser.add_argument('-k', '--key-file', required=False, type=argparse.FileType("r"), help="File containing keys of tag to write (exported with fchk --export)")
        parser.set_defaults(maxSectors=16)
        return parser

    def on_exec(self, args: argparse.Namespace):
        data = bytearray(0)
        if args.dump_file is not None:
            print("Reading dump file")
            data = args.dump_file.read()
        elif args.key_file is not None:
            print("Reading tag memory")
            # read keys from file
            keys = list()
            for line in args.key_file.readlines():
                a, b = (bytes.fromhex(h) for h in line[:-1].split(":"))
                keys.append((a, b))
            if len(keys) != args.maxSectors:
                raise ArgsParserError(f"Invalid key file. Found {len(keys)}, expected {args.maxSectors}")
            # iterate over blocks
            for blk in range(0, args.maxSectors * 4):
                resp = None
                try:
                    # first try with key B
                    resp = self.cmd.mf1_read_one_block(blk, MfcKeyType.B, keys[blk//4][1])
                except UnexpectedResponseError:
                    # ignore read errors at this stage as we want to try key A
                    pass
                if not resp:
                    # try with key A if B was unsuccessful
                    # this will raise an exception if key A fails too
                    resp = self.cmd.mf1_read_one_block(blk, MfcKeyType.A, keys[blk//4][0])
                data.extend(resp)
        else:
            raise ArgsParserError("Missing args. Specify --dump-file (-d) or --key-file (-k)")
        print_mem_dump(data,16)

@mf.command('value')
class HFMFVALUE(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'MIFARE Classic value block commands'

        operator_group = parser.add_mutually_exclusive_group()
        operator_group.add_argument('--get', action='store_true', help="get value from src block")
        operator_group.add_argument('--set', type=int, required=False, metavar="<dec>",
                            help="set value X (-2147483647 ~ 2147483647) to src block")
        operator_group.add_argument('--inc', type=int, required=False, metavar="<dec>",
                            help="increment value by X (0 ~ 2147483647) from src to dst")
        operator_group.add_argument('--dec', type=int, required=False, metavar="<dec>",
                            help="decrement value by X (0 ~ 2147483647) from src to dst")
        operator_group.add_argument('--res', '--cp', action='store_true', help="copy value from src to dst (Restore and Transfer)")

        parser.add_argument('--blk', '--src-block', type=int, required=True, metavar="<dec>",
                            help="block number of src")
        srctype_group = parser.add_mutually_exclusive_group()
        srctype_group.add_argument('-a', '-A', action='store_true', help="key of src is A key (default)")
        srctype_group.add_argument('-b', '-B', action='store_true', help="key of src is B key")
        parser.add_argument('-k', '--src-key', type=str, required=True, metavar="<hex>", help="key of src")

        parser.add_argument('--tblk', '--dst-block', type=int, metavar="<dec>",
                            help="block number of dst (default to src)")
        dsttype_group = parser.add_mutually_exclusive_group()
        dsttype_group.add_argument('--ta', '--tA', action='store_true', help="key of dst is A key (default to src)")
        dsttype_group.add_argument('--tb', '--tB', action='store_true', help="key of dst is B key (default to src)")
        parser.add_argument('--tkey', '--dst-key', type=str, metavar="<hex>", help="key of dst (default to src)")

        return parser

    def on_exec(self, args: argparse.Namespace):
        # print(args)
        # src
        src_blk = args.blk
        src_type = MfcKeyType.B if args.b is not False else MfcKeyType.A
        src_key = args.src_key
        if not re.match(r"^[a-fA-F0-9]{12}$", src_key):
            print("src_key must include 12 HEX symbols")
            return
        src_key = bytearray.fromhex(src_key)
        # print(src_blk, src_type, src_key)

        if args.get is not False:
            self.get_value(src_blk, src_type, src_key)
            return
        elif args.set is not None:
            self.set_value(src_blk, src_type, src_key, args.set)
            return

        # dst
        dst_blk = args.tblk if args.tblk is not None else src_blk
        dst_type = MfcKeyType.A if args.ta is not False else (MfcKeyType.B if args.tb is not False else src_type)
        dst_key = args.tkey if args.tkey is not None else args.src_key
        if not re.match(r"^[a-fA-F0-9]{12}$", dst_key):
            print("dst_key must include 12 HEX symbols")
            return
        dst_key = bytearray.fromhex(dst_key)
        # print(dst_blk, dst_type, dst_key)
        
        if args.inc is not None:
            self.inc_value(src_blk, src_type, src_key, args.inc, dst_blk, dst_type, dst_key)
            return
        elif args.dec is not None:
            self.dec_value(src_blk, src_type, src_key, args.dec, dst_blk, dst_type, dst_key)
            return
        elif args.res is not False:
            self.res_value(src_blk, src_type, src_key, dst_blk, dst_type, dst_key)
            return
        else:
            raise ArgsParserError("Please specify a value command")

    def get_value(self, block, type, key):
        resp = self.cmd.mf1_read_one_block(block, type, key)
        val1, val2, val3, adr1, adr2, adr3, adr4 = struct.unpack("<iiiBBBB", resp)
        # print(f"{val1}, {val2}, {val3}, {adr1}, {adr2}, {adr3}, {adr4}")
        if (val1 != val3) or (val1 + val2 != -1):
            print(f" - {color_string((CR, f'Invalid value of value block: {resp.hex()}'))}")
            return
        if (adr1 != adr3) or (adr2 != adr4) or (adr1 + adr2 != 0xFF):
            print(f" - {color_string((CR, f'Invalid address of value block: {resp.hex()}'))}")
            return
        print(f" - block[{block}] = {color_string((CG, f'{{ value: {val1}, adr: {adr1} }}'))}")

    def set_value(self, block, type, key, value):
        if value < -2147483647 or value > 2147483647:
            raise ArgsParserError(f"Set value must be between -2147483647 and 2147483647. Got {value}")
        adr_inverted = 0xFF - block
        data = struct.pack("<iiiBBBB", value, -value - 1, value, block, adr_inverted, block, adr_inverted)
        resp = self.cmd.mf1_write_one_block(block, type, key, data)
        if resp:
            print(f" - {color_string((CG, 'Set done.'))}")
            self.get_value(block, type, key)
        else:
            print(f" - {color_string((CR, 'Set fail.'))}")

    def inc_value(self, src_blk, src_type, src_key, value, dst_blk, dst_type, dst_key):
        if value < 0 or value > 2147483647:
            raise ArgsParserError(f"Increment value must be between 0 and 2147483647. Got {value}")
        resp = self.cmd.mf1_manipulate_value_block(
            src_blk, src_type, src_key, 
            MfcValueBlockOperator.INCREMENT, value,
            dst_blk, dst_type, dst_key
        )
        if resp:
            print(f" - {color_string((CG, 'Increment done.'))}")
            self.get_value(dst_blk, dst_type, dst_key)
        else:
            print(f" - {color_string((CR, 'Increment fail.'))}")
    
    def dec_value(self, src_blk, src_type, src_key, value, dst_blk, dst_type, dst_key):
        if value < 0 or value > 2147483647:
            raise ArgsParserError(f"Decrement value must be between 0 and 2147483647. Got {value}")
        resp = self.cmd.mf1_manipulate_value_block(
            src_blk, src_type, src_key, 
            MfcValueBlockOperator.DECREMENT, value,
            dst_blk, dst_type, dst_key
        )
        if resp:
            print(f" - {color_string((CG, 'Decrement done.'))}")
            self.get_value(dst_blk, dst_type, dst_key)
        else:
            print(f" - {color_string((CR, 'Decrement fail.'))}")

    def res_value(self, src_blk, src_type, src_key, dst_blk, dst_type, dst_key):
        resp = self.cmd.mf1_manipulate_value_block(
            src_blk, src_type, src_key, 
            MfcValueBlockOperator.RESTORE, 0,
            dst_blk, dst_type, dst_key
        )
        if resp:
            print(f" - {color_string((CG, 'Restore done.'))}")
            self.get_value(dst_blk, dst_type, dst_key)
        else:
            print(f" - {color_string((CR, 'Restore fail.'))}")


@mf.command('elog')
class HFMFELog(DeviceRequiredUnit):
    detection_log_size = 18

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'MF1 Detection log count/decrypt'
        parser.add_argument('--decrypt', action='store_true', help="Decrypt key from MF1 log list")
        return parser

    def decrypt_by_list(self, rs: list):
        """
            Decrypt key from reconnaissance log list

        :param rs:
        :return:
        """
        msg1 = f"  > {len(rs)} records => "
        msg2 = f"/{(len(rs)*(len(rs)-1))//2} combinations. "
        msg3 = " key(s) found"
        n = 1
        gen = ItemGenerator(rs)
        with Pool(cpu_count()) as pool:
            for result in pool.imap(_run_mfkey32v2, gen):
                # TODO: if some keys already recovered, test them on item before running mfkey32 on item
                if result is not None:
                    gen.key_found(*result)
                print(f"{msg1}{n}{msg2}{len(gen.keys)}{msg3}\r", end="")
                n += 1
        print()
        return gen.keys

    def on_exec(self, args: argparse.Namespace):
        if not args.decrypt:
            count = self.cmd.mf1_get_detection_count()
            print(f" - MF1 detection log count = {count}")
            return
        index = 0
        count = self.cmd.mf1_get_detection_count()
        if count == 0:
            print(" - No detection log to download")
            return
        print(f" - MF1 detection log count = {count}, start download", end="")
        result_list = []
        while index < count:
            tmp = self.cmd.mf1_get_detection_log(index)
            recv_count = len(tmp)
            index += recv_count
            result_list.extend(tmp)
            print("."*recv_count, end="")
        print()
        print(f" - Download done ({len(result_list)} records), start parse and decrypt")
        # classify
        result_maps = {}
        for item in result_list:
            uid = item['uid']
            if uid not in result_maps:
                result_maps[uid] = {}
            block = item['block']
            if block not in result_maps[uid]:
                result_maps[uid][block] = {}
            type = item['type']
            if type not in result_maps[uid][block]:
                result_maps[uid][block][type] = []

            result_maps[uid][block][type].append(item)

        for uid in result_maps.keys():
            print(f" - Detection log for uid [{uid.upper()}]")
            result_maps_for_uid = result_maps[uid]
            for block in result_maps_for_uid:
                print(f"  > Block {block} detect log decrypting...")
                if 'A' in result_maps_for_uid[block]:
                    # print(f" - A record: { result_maps[block]['A'] }")
                    records = result_maps_for_uid[block]['A']
                    if len(records) > 1:
                        result_maps[uid][block]['A'] = self.decrypt_by_list(records)
                    else:
                        print(f"  > {len(records)} record")
                if 'B' in result_maps_for_uid[block]:
                    # print(f" - B record: { result_maps[block]['B'] }")
                    records = result_maps_for_uid[block]['B']
                    if len(records) > 1:
                        result_maps[uid][block]['B'] = self.decrypt_by_list(records)
                    else:
                        print(f"  > {len(records)} record")
            print("  > Result ---------------------------")
            for block in result_maps_for_uid.keys():
                if 'A' in result_maps_for_uid[block]:
                    print(f"  > Block {block}, A key result: {result_maps_for_uid[block]['A']}")
                if 'B' in result_maps_for_uid[block]:
                    print(f"  > Block {block}, B key result: {result_maps_for_uid[block]['B']}")
        return


@mf.command('eload')
class HFMFELoad(SlotIndexArgsAndGoUnit, DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Load data to emulator memory'
        self.add_slot_args(parser)
        parser.add_argument('-f', '--file', type=str, required=True, help="file path")
        parser.add_argument('-t', '--type', type=str, required=False, help="content type", choices=['bin', 'hex'])
        return parser

    def on_exec(self, args: argparse.Namespace):
        file = args.file
        if args.type is None:
            if file.endswith('.bin'):
                content_type = 'bin'
            elif file.endswith('.eml'):
                content_type = 'hex'
            else:
                raise Exception("Unknown file format, Specify content type with -t option")
        else:
            content_type = args.type
        buffer = bytearray()

        with open(file, mode='rb') as fd:
            if content_type == 'bin':
                buffer.extend(fd.read())
            if content_type == 'hex':
                buffer.extend(bytearray.fromhex(fd.read().decode()))

        if len(buffer) % 16 != 0:
            raise Exception("Data block not align for 16 bytes")
        if len(buffer) / 16 > 256:
            raise Exception("Data block memory overflow")

        index = 0
        block = 0
        max_blocks = (self.device_com.data_max_length - 1) // 16
        while index + 16 < len(buffer):
            # split a block from buffer
            block_data = buffer[index: index + 16*max_blocks]
            n_blocks = len(block_data) // 16
            index += 16*n_blocks
            # load to device
            self.cmd.mf1_write_emu_block_data(block, block_data)
            print('.'*n_blocks, end='')
            block += n_blocks
        print("\n - Load success")


@mf.command('esave')
class HFMFESave(SlotIndexArgsAndGoUnit, DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Read data from emulator memory'
        self.add_slot_args(parser)
        parser.add_argument('-f', '--file', type=str, required=True, help="file path")
        parser.add_argument('-t', '--type', type=str, required=False, help="content type", choices=['bin', 'hex'])
        return parser

    def on_exec(self, args: argparse.Namespace):
        file = args.file
        if args.type is None:
            if file.endswith('.bin'):
                content_type = 'bin'
            elif file.endswith('.eml'):
                content_type = 'hex'
            else:
                raise Exception("Unknown file format, Specify content type with -t option")
        else:
            content_type = args.type

        selected_slot = self.cmd.get_active_slot()
        slot_info = self.cmd.get_slot_info()
        tag_type = TagSpecificType(slot_info[selected_slot]['hf'])
        if tag_type == TagSpecificType.MIFARE_Mini:
            block_count = 20
        elif tag_type == TagSpecificType.MIFARE_1024:
            block_count = 64
        elif tag_type == TagSpecificType.MIFARE_2048:
            block_count = 128
        elif tag_type == TagSpecificType.MIFARE_4096:
            block_count = 256
        else:
            raise Exception("Card in current slot is not Mifare Classic/Plus in SL1 mode")

        index = 0
        data = bytearray(0)
        max_blocks = self.device_com.data_max_length // 16
        while block_count > 0:
            chunk_count = min(block_count, max_blocks)
            data.extend(self.cmd.mf1_read_emu_block_data(index, chunk_count))
            index += chunk_count
            block_count -= chunk_count
            print('.'*chunk_count, end='')

        with open(file, 'wb') as fd:
            if content_type == 'hex':
                for i in range(len(data) // 16):
                    fd.write(binascii.hexlify(data[i*16:(i+1)*16])+b'\n')
            else:
                fd.write(data)
        print("\n - Read success")

@mf.command('eview')
class HFMFEView(SlotIndexArgsAndGoUnit, DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'View data from emulator memory'
        self.add_slot_args(parser)
        return parser
    
    def on_exec(self, args: argparse.Namespace):
        selected_slot = self.cmd.get_active_slot()
        slot_info = self.cmd.get_slot_info()
        tag_type = TagSpecificType(slot_info[selected_slot]['hf'])      
        
        if tag_type == TagSpecificType.MIFARE_Mini:
            block_count = 20
        elif tag_type == TagSpecificType.MIFARE_1024:
            block_count = 64
        elif tag_type == TagSpecificType.MIFARE_2048:
            block_count = 128
        elif tag_type == TagSpecificType.MIFARE_4096:
            block_count = 256
        else:
            raise Exception("Card in current slot is not Mifare Classic/Plus in SL1 mode")
        index = 0
        data = bytearray(0)
        max_blocks = self.device_com.data_max_length // 16
        while block_count > 0:
            # read all the blocks
            chunk_count = min(block_count, max_blocks)
            data.extend(self.cmd.mf1_read_emu_block_data(index, chunk_count))
            index += chunk_count
            block_count -= chunk_count
        print_mem_dump(data,16)

@mf.command('econfig')
class HFMFEConfig(SlotIndexArgsAndGoUnit, HF14AAntiCollArgsUnit, DeviceRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Settings of Mifare Classic emulator'
        self.add_slot_args(parser)
        self.add_hf14a_anticoll_args(parser)
        gen1a_group = parser.add_mutually_exclusive_group()
        gen1a_group.add_argument('--enable-gen1a', action='store_true', help="Enable Gen1a magic mode")
        gen1a_group.add_argument('--disable-gen1a', action='store_true', help="Disable Gen1a magic mode")
        gen2_group = parser.add_mutually_exclusive_group()
        gen2_group.add_argument('--enable-gen2', action='store_true', help="Enable Gen2 magic mode")
        gen2_group.add_argument('--disable-gen2', action='store_true', help="Disable Gen2 magic mode")
        block0_group = parser.add_mutually_exclusive_group()
        block0_group.add_argument('--enable-block0', action='store_true',
                                  help="Use anti-collision data from block 0 for 4 byte UID tags")
        block0_group.add_argument('--disable-block0', action='store_true', help="Use anti-collision data from settings")
        write_names = [w.name for w in MifareClassicWriteMode.list()]
        help_str = "Write Mode: " + ", ".join(write_names)
        parser.add_argument('--write', type=str, help=help_str, metavar="MODE", choices=write_names)
        log_group = parser.add_mutually_exclusive_group()
        log_group.add_argument('--enable-log', action='store_true', help="Enable logging of MFC authentication data")
        log_group.add_argument('--disable-log', action='store_true', help="Disable logging of MFC authentication data")
        return parser

    def on_exec(self, args: argparse.Namespace):
        # collect current settings
        anti_coll_data = self.cmd.hf14a_get_anti_coll_data()
        if len(anti_coll_data) == 0:
            print(f"{color_string((CR, f'Slot {self.slot_num} does not contain any HF 14A config'))}")
            return
        uid = anti_coll_data['uid']
        atqa = anti_coll_data['atqa']
        sak = anti_coll_data['sak']
        ats = anti_coll_data['ats']
        slotinfo = self.cmd.get_slot_info()
        fwslot = SlotNumber.to_fw(self.slot_num)
        hf_tag_type = TagSpecificType(slotinfo[fwslot]['hf'])
        if hf_tag_type not in [
            TagSpecificType.MIFARE_Mini,
            TagSpecificType.MIFARE_1024,
            TagSpecificType.MIFARE_2048,
            TagSpecificType.MIFARE_4096,
        ]:
            print(f"{color_string((CR, f'Slot {self.slot_num} not configured as MIFARE Classic'))}")
            return
        mfc_config = self.cmd.mf1_get_emulator_config()
        gen1a_mode = mfc_config["gen1a_mode"]
        gen2_mode = mfc_config["gen2_mode"]
        block_anti_coll_mode = mfc_config["block_anti_coll_mode"]
        write_mode = MifareClassicWriteMode(mfc_config["write_mode"])
        detection = mfc_config["detection"]
        change_requested, change_done, uid, atqa, sak, ats = self.update_hf14a_anticoll(args, uid, atqa, sak, ats)
        if args.enable_gen1a:
            change_requested = True
            if not gen1a_mode:
                gen1a_mode = True
                self.cmd.mf1_set_gen1a_mode(gen1a_mode)
                change_done = True
            else:
                print(f'{color_string((CY, "Requested gen1a already enabled"))}')
        elif args.disable_gen1a:
            change_requested = True
            if gen1a_mode:
                gen1a_mode = False
                self.cmd.mf1_set_gen1a_mode(gen1a_mode)
                change_done = True
            else:
                print(f'{color_string((CY, "Requested gen1a already disabled"))}')
        if args.enable_gen2:
            change_requested = True
            if not gen2_mode:
                gen2_mode = True
                self.cmd.mf1_set_gen2_mode(gen2_mode)
                change_done = True
            else:
                print(f'{color_string((CY, "Requested gen2 already enabled"))}')
        elif args.disable_gen2:
            change_requested = True
            if gen2_mode:
                gen2_mode = False
                self.cmd.mf1_set_gen2_mode(gen2_mode)
                change_done = True
            else:
                print(f'{color_string((CY, "Requested gen2 already disabled"))}')
        if args.enable_block0:
            change_requested = True
            if not block_anti_coll_mode:
                block_anti_coll_mode = True
                self.cmd.mf1_set_block_anti_coll_mode(block_anti_coll_mode)
                change_done = True
            else:
                print(f'{color_string((CY, "Requested block0 anti-coll mode already enabled"))}')
        elif args.disable_block0:
            change_requested = True
            if block_anti_coll_mode:
                block_anti_coll_mode = False
                self.cmd.mf1_set_block_anti_coll_mode(block_anti_coll_mode)
                change_done = True
            else:
                print(f'{color_string((CY, "Requested block0 anti-coll mode already disabled"))}')
        if args.write is not None:
            change_requested = True
            new_write_mode = MifareClassicWriteMode[args.write]
            if new_write_mode != write_mode:
                write_mode = new_write_mode
                self.cmd.mf1_set_write_mode(write_mode)
                change_done = True
            else:
                print(f'{color_string((CY, "Requested write mode already set"))}')
        if args.enable_log:
            change_requested = True
            if not detection:
                detection = True
                self.cmd.mf1_set_detection_enable(detection)
                change_done = True
            else:
                print(f'{color_string((CY, "Requested logging of MFC authentication data already enabled"))}')
        elif args.disable_log:
            change_requested = True
            if detection:
                detection = False
                self.cmd.mf1_set_detection_enable(detection)
                change_done = True
            else:
                print(f'{color_string((CY, "Requested logging of MFC authentication data already disabled"))}')

        if change_done:
            print(' - MF1 Emulator settings updated')
        if not change_requested:
            enabled_str = color_string((CG, "enabled"))
            disabled_str = color_string((CR, "disabled"))
            atqa_string = f"{atqa.hex().upper()} (0x{int.from_bytes(atqa, byteorder='little'):04x})"
            print(f'- {"Type:":40}{color_string((CY, hf_tag_type))}')
            print(f'- {"UID:":40}{color_string((CY, uid.hex().upper()))}')
            print(f'- {"ATQA:":40}{color_string((CY, atqa_string))}')
            print(f'- {"SAK:":40}{color_string((CY, sak.hex().upper()))}')
            if len(ats) > 0:
                print(f'- {"ATS:":40}{color_string((CY, ats.hex().upper()))}')
            print(
                f'- {"Gen1A magic mode:":40}{f"{enabled_str}" if gen1a_mode else f"{disabled_str}"}')
            print(
                f'- {"Gen2 magic mode:":40}{f"{enabled_str}" if gen2_mode else f"{disabled_str}"}')
            print(
                f'- {"Use anti-collision data from block 0:":40}'
                f'{f"{enabled_str}" if block_anti_coll_mode else f"{disabled_str}"}')
            try:
                print(f'- {"Write mode:":40}{color_string((CY, MifareClassicWriteMode(write_mode)))}')
            except ValueError:
                print(f'- {"Write mode:":40}{color_string((CR, "invalid value!"))}')
            print(
                f'- {"Log (mfkey32) mode:":40}{f"{enabled_str}" if detection else f"{disabled_str}"}')

import argparse
import re

from chameleon.chameleon_enum import (
    MifareClassicPrngType,
)
from chameleon.chameleon_utils import (
    CR,
    CY,
    color_string,
)
from chameleon.commands.util import (
    ArgumentParserNoExit,
    CLITree,
    ReaderRequiredUnit,
)


iso14443a = CLITree("14a", "ISO14443-A commands")

# NXP IDs based on https://www.nxp.com/docs/en/application-note/AN10833.pdf
type_id_SAK_dict = {0x00: "MIFARE Ultralight Classic/C/EV1/Nano | NTAG 2xx",
                    0x08: "MIFARE Classic 1K | Plus SE 1K | Plug S 2K | Plus X 2K",
                    0x09: "MIFARE Mini 0.3k",
                    0x10: "MIFARE Plus 2K",
                    0x11: "MIFARE Plus 4K",
                    0x18: "MIFARE Classic 4K | Plus S 4K | Plus X 4K",
                    0x19: "MIFARE Classic 2K",
                    0x20: "MIFARE Plus EV1/EV2 | DESFire EV1/EV2/EV3 | DESFire Light | NTAG 4xx | "
                          "MIFARE Plus S 2/4K | MIFARE Plus X 2/4K | MIFARE Plus SE 1K",
                    0x28: "SmartMX with MIFARE Classic 1K",
                    0x38: "SmartMX with MIFARE Classic 4K",
                    }

@iso14443a.command('scan')
class HF14AScan(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Scan 14a tag, and print basic information'
        return parser

    def check_mf1_nt(self):
        # detect mf1 support
        if self.cmd.mf1_detect_support():
            # detect prng
            print("- Mifare Classic technology")
            prng_type = self.cmd.mf1_detect_prng()
            print(f"  # Prng: {MifareClassicPrngType(prng_type)}")

    def sak_info(self, data_tag):
        # detect the technology in use based on SAK
        int_sak = data_tag['sak'][0]
        if int_sak in type_id_SAK_dict:
            print(f"- Guessed type(s) from SAK: {type_id_SAK_dict[int_sak]}")

    def scan(self, deep=False):
        resp = self.cmd.hf14a_scan()
        if resp is not None:
            for data_tag in resp:
                print(f"- UID  : {data_tag['uid'].hex().upper()}")
                print(f"- ATQA : {data_tag['atqa'].hex().upper()} "
                      f"(0x{int.from_bytes(data_tag['atqa'], byteorder='little'):04x})")
                print(f"- SAK  : {data_tag['sak'].hex().upper()}")
                if len(data_tag['ats']) > 0:
                    print(f"- ATS  : {data_tag['ats'].hex().upper()}")
                if deep:
                    self.sak_info(data_tag)
                    # TODO: following checks cannot be done yet if multiple cards are present
                    if len(resp) == 1:
                        self.check_mf1_nt()
                        # TODO: check for ATS support on 14A3 tags
                    else:
                        print("Multiple tags detected, skipping deep tests...")
        else:
            print("ISO14443-A Tag no found")

    def on_exec(self, args: argparse.Namespace):
        self.scan()


@iso14443a.command('info')
class HF14AInfo(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Scan 14a tag, and print detail information'
        return parser

    def on_exec(self, args: argparse.Namespace):
        scan = HF14AScan()
        scan.device_com = self.device_com
        scan.scan(deep=True)


@iso14443a.command('raw')
class HF14ARaw(ReaderRequiredUnit):

    def bool_to_bit(self, value):
        return 1 if value else 0

    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.formatter_class = argparse.RawDescriptionHelpFormatter
        parser.description = 'Send raw command'
        parser.add_argument('-a', '--activate-rf', help="Active signal field ON without select",
                            action='store_true', default=False,)
        parser.add_argument('-s', '--select-tag', help="Active signal field ON with select",
                            action='store_true', default=False,)
        # TODO: parser.add_argument('-3', '--type3-select-tag',
        #           help="Active signal field ON with ISO14443-3 select (no RATS)", action='store_true', default=False,)
        parser.add_argument('-d', '--data', type=str, metavar="<hex>", help="Data to be sent")
        parser.add_argument('-b', '--bits', type=int, metavar="<dec>",
                            help="Number of bits to send. Useful for send partial byte")
        parser.add_argument('-c', '--crc', help="Calculate and append CRC", action='store_true', default=False,)
        parser.add_argument('-r', '--no-response', help="Do not read response", action='store_true', default=False,)
        parser.add_argument('-cc', '--crc-clear', help="Verify and clear CRC of received data",
                            action='store_true', default=False,)
        parser.add_argument('-k', '--keep-rf', help="Keep signal field ON after receive",
                            action='store_true', default=False,)
        parser.add_argument('-t', '--timeout', type=int, metavar="<dec>", help="Timeout in ms", default=100)
        parser.epilog = """
examples/notes:
  hf 14a raw -b 7 -d 40 -k
  hf 14a raw -d 43 -k
  hf 14a raw -d 3000 -c
  hf 14a raw -sc -d 6000
"""
        return parser

    def on_exec(self, args: argparse.Namespace):
        options = {
            'activate_rf_field': self.bool_to_bit(args.activate_rf),
            'wait_response': self.bool_to_bit(not args.no_response),
            'append_crc': self.bool_to_bit(args.crc),
            'auto_select': self.bool_to_bit(args.select_tag),
            'keep_rf_field': self.bool_to_bit(args.keep_rf),
            'check_response_crc': self.bool_to_bit(args.crc_clear),
            # 'auto_type3_select': self.bool_to_bit(args.type3-select-tag),
        }
        data: str = args.data
        if data is not None:
            data = data.replace(' ', '')
            if re.match(r'^[0-9a-fA-F]+$', data):
                if len(data) % 2 != 0:
                    print(f" [!] {color_string((CR, 'The length of the data must be an integer multiple of 2.'))}")
                    return
                else:
                    data_bytes = bytes.fromhex(data)
            else:
                print(f" [!] {color_string((CR, 'The data must be a HEX string'))}")
                return
        else:
            data_bytes = []
        if args.bits is not None and args.crc:
            print(f" [!] {color_string((CR, '--bits and --crc are mutually exclusive'))}")
            return

        # Exec 14a raw cmd.
        resp = self.cmd.hf14a_raw(options, args.timeout, data_bytes, args.bits)
        if len(resp) > 0:
            print(
                # print head
                " - " +
                # print data
                ' '.join([hex(byte).replace('0x', '').rjust(2, '0') for byte in resp])
            )
        else:
            print(f" [*] {color_string((CY, 'No response'))}")

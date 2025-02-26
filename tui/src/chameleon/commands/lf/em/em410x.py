import argparse

from chameleon.chameleon_utils import (
    CG,
    color_string,
)
from chameleon.commands.util import (
    ArgumentParserNoExit,
    CLITree,
    LFEMIdArgsUnit,
    ReaderRequiredUnit,
    SlotIndexArgsAndGoUnit,
)


em410x = CLITree("410x", "EM410x commands")

@em410x.command('read')
class LFEMRead(ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Scan em410x tag and print id'
        return parser

    def on_exec(self, args: argparse.Namespace):
        id = self.cmd.em410x_scan()
        print(f" - EM410x ID(10H): {color_string((CG, id.hex()))}")


@em410x.command('write')
class LFEM410xWriteT55xx(LFEMIdArgsUnit, ReaderRequiredUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Write em410x id to t55xx'
        return self.add_card_arg(parser, required=True)

    def before_exec(self, args: argparse.Namespace):
        b1 = super(LFEMIdArgsUnit, self).before_exec(args)
        b2 = super(ReaderRequiredUnit, self).before_exec(args)
        return b1 and b2

    def on_exec(self, args: argparse.Namespace):
        id_hex = args.id
        id_bytes = bytes.fromhex(id_hex)
        self.cmd.em410x_write_to_t55xx(id_bytes)
        print(f" - EM410x ID(10H): {id_hex} write done.")


@em410x.command('econfig')
class LFEM410xEconfig(SlotIndexArgsAndGoUnit, LFEMIdArgsUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Set simulated em410x card id'
        self.add_slot_args(parser)
        self.add_card_arg(parser)
        return parser

    def on_exec(self, args: argparse.Namespace):
        if args.id is not None:
            self.cmd.em410x_set_emu_id(bytes.fromhex(args.id))
            print(' - Set em410x tag id success.')
        else:
            response = self.cmd.em410x_get_emu_id()
            print(' - Get em410x tag id success.')
            print(f'ID: {response.hex()}')

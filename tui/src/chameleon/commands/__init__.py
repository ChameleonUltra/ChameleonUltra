import argparse
import os
import sys

from datetime import datetime

from chameleon.chameleon_utils import (
    C0,
    CB,
    CC,
    CG,
    CR,
    CY,
    color_string,
)
from chameleon.commands.util import (
    ArgumentParserNoExit,
    BaseCLIUnit,
    CLITree,
)


root = CLITree(root=True, ldr=__loader__)

@root.command('clear')
class RootClear(BaseCLIUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Clear screen'
        return parser

    def on_exec(self, args: argparse.Namespace):
        os.system('clear' if os.name == 'posix' else 'cls')


@root.command('rem')
class RootRem(BaseCLIUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Timestamped comment'
        parser.add_argument('comment', nargs='*', help='Your comment')
        return parser

    def on_exec(self, args: argparse.Namespace):
        # precision: second
        # iso_timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        # precision: nanosecond (note that the comment will take some time too, ~75ns, check your system)
        iso_timestamp = datetime.utcnow().isoformat() + 'Z'
        comment = ' '.join(args.comment)
        print(f"{iso_timestamp} remark: {comment}")


@root.command('exit')
class RootExit(BaseCLIUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Exit client'
        return parser

    def on_exec(self, args: argparse.Namespace):
        print("Bye, thank you.  ^.^ ")
        self.device_com.close()
        sys.exit(996)


@root.command('dump_help')
class RootDumpHelp(BaseCLIUnit):
    def args_parser(self) -> ArgumentParserNoExit:
        parser = ArgumentParserNoExit()
        parser.description = 'Dump available commands'
        parser.add_argument('-d', '--show-desc', action='store_true', help="Dump full command description")
        parser.add_argument('-g', '--show-groups', action='store_true', help="Dump command groups as well")
        return parser

    @staticmethod
    def dump_help(cmd_node, depth=0, dump_cmd_groups=False, dump_description=False):
        visual_col1_width = 28
        col1_width = visual_col1_width + len(f"{CG}{C0}")
        if cmd_node.cls:
            p = cmd_node.cls().args_parser()
            assert p is not None
            if dump_description:
                p.print_help()
            else:
                cmd_title = color_string((CG, cmd_node.fullname))
                print(f"{cmd_title}".ljust(col1_width), end="")
                p.prog = " " * (visual_col1_width - len("usage: ") - 1)
                usage = p.format_usage().removeprefix("usage: ").strip()
                print(color_string((CY, usage)))
        else:
            if dump_cmd_groups and not cmd_node.root:
                if dump_description:
                    print("=" * 80)
                    print(color_string((CR, cmd_node.fullname)))
                    print(color_string((CC, cmd_node.help_text)))
                else:
                    print(color_string((CB, f"== {cmd_node.fullname} ==")))
            for child in cmd_node.children:
                RootDumpHelp.dump_help(child, depth + 1, dump_cmd_groups, dump_description)

    def on_exec(self, args: argparse.Namespace):
        self.dump_help(root, dump_cmd_groups=args.show_groups, dump_description=args.show_desc)

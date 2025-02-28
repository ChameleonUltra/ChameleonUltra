import argparse
import traceback

from pathlib import Path

import colorama

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import Completer, NestedCompleter, WordCompleter
from prompt_toolkit.completion.base import Completion
from prompt_toolkit.document import Document
from prompt_toolkit.formatted_text import ANSI
from prompt_toolkit.history import FileHistory

from chameleon.chameleon_com import ChameleonCom
from chameleon.chameleon_utils import (
    CG,
    CR,
    CY,
    ArgsParserError,
    ArgumentParserNoExit,
    ParserExitIntercept,
    UnexpectedResponseError,
    color_string,
)
from chameleon.commands import root


# create by http://patorjk.com/software/taag/#p=display&f=ANSI%20Shadow&t=Chameleon%20Ultra
BANNER = """
 ██████╗██╗  ██╗ █████╗ ██╗   ██╗███████╗██╗     ███████╗ █████╗ ██╗  ██╗
██╔════╝██║  ██║██╔══██╗███╗ ███║██╔════╝██║     ██╔════╝██╔══██╗███╗ ██║
██║     ███████║███████║████████║█████╗  ██║     █████╗  ██║  ██║████╗██║
██║     ██╔══██║██╔══██║██╔██╔██║██╔══╝  ██║     ██╔══╝  ██║  ██║██╔████║
╚██████╗██║  ██║██║  ██║██║╚═╝██║███████╗███████╗███████╗╚█████╔╝██║╚███║
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝╚══════╝╚══════╝╚══════╝ ╚════╝ ╚═╝ ╚══╝
"""

ULTRA = r"""
                                                                ╦ ╦╦ ╔╦╗╦═╗╔═╗
                                                   ███████      ║ ║║  ║ ╠╦╝╠═╣
                                                                ╚═╝╩═╝╩ ╩╚═╩ ╩
"""

LITE = r"""
                                                                ╦  ╦╔╦╗╔═╗
                                                   ███████      ║  ║ ║ ║╣
                                                                ╩═╝╩ ╩ ╚═╝
"""

class ArgparseCompleter(Completer):
    """
    Completer instance for autocompletion of ArgumentParser arguments

    :param parser: ArgumentParser instance
    """

    def __init__(self, parser) -> None:
        self.parser: ArgumentParserNoExit = parser

    def check_tokens(self, parsed, unparsed):
        suggestions = {}

        def check_arg(tokens):
            return tokens and tokens[0].startswith('-')

        if not parsed and not unparsed:
            # No tokens detected, just show all flags
            for action in self.parser._actions:
                for opt in action.option_strings:
                    suggestions[opt] = action.help
            return [], [], suggestions

        token = unparsed.pop(0)

        for action in self.parser._actions:
            if any(opt == token for opt in action.option_strings):
                # Argument fully matches the token
                parsed.append(token)

                if action.choices:
                    # Autocomplete with choices
                    if unparsed:
                        # Autocomplete values
                        value = unparsed.pop(0)
                        for choice in action.choices:
                            if str(choice).startswith(value):
                                suggestions[str(choice)] = None

                        parsed.append(value)

                        if check_arg(unparsed):
                            parsed, unparsed, suggestions = self.check_tokens(
                                parsed, unparsed)

                    else:
                        # Show all possible values
                        for choice in action.choices:
                            suggestions[str(choice)] = None

                    break
                else:
                    # No choices, process further arguments
                    if check_arg(unparsed):
                        parsed, unparsed, suggestions = self.check_tokens(
                            parsed, unparsed)
                    break
            elif any(opt.startswith(token) for opt in action.option_strings):
                for opt in action.option_strings:
                    if opt.startswith(token):
                        suggestions[opt] = action.help

        if suggestions:
            unparsed.insert(0, token)

        return parsed, unparsed, suggestions

    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        word_before_cursor = document.text_before_cursor.split(' ')[-1]

        _, _, suggestions = self.check_tokens(list(), text.split())

        for key, suggestion in suggestions.items():
            yield Completion(key, -len(word_before_cursor), display=key, display_meta=suggestion)


class CustomNestedCompleter(NestedCompleter):
    """
    Copy of the NestedCompleter class that accepts a CLITree object and
    supports meta_dict for descriptions
    """

    def __init__(
        self, options, ignore_case: bool = True, meta_dict: dict = {}
    ) -> None:
        self.options = options
        self.ignore_case = ignore_case
        self.meta_dict = meta_dict

    def __repr__(self) -> str:
        return f"CustomNestedCompleter({self.options!r}, ignore_case={self.ignore_case!r})"

    @classmethod
    def from_clitree(cls, node):
        options = {}
        meta_dict = {}

        for child_node in node.children:
            if child_node.cls:
                # CLITree is a standalone command with arguments
                options[child_node.name] = ArgparseCompleter(
                    child_node.cls().args_parser())
            else:
                # CLITree is a command group
                options[child_node.name] = cls.from_clitree(child_node)
                meta_dict[child_node.name] = child_node.help_text

        return cls(options, meta_dict=meta_dict)

    def get_completions(self, document, complete_event):
        # Split document.
        text = document.text_before_cursor.lstrip()
        stripped_len = len(document.text_before_cursor) - len(text)

        # If there is a space, check for the first term, and use a sub_completer.
        if " " in text:
            first_term = text.split()[0]
            completer = self.options.get(first_term)

            # If we have a sub completer, use this for the completions.
            if completer is not None:
                remaining_text = text[len(first_term):].lstrip()
                move_cursor = len(text) - len(remaining_text) + stripped_len

                new_document = Document(
                    remaining_text,
                    cursor_position=document.cursor_position - move_cursor,
                )

                yield from completer.get_completions(new_document, complete_event)

        # No space in the input: behave exactly like `WordCompleter`.
        else:
            completer = WordCompleter(
                list(self.options.keys()), ignore_case=self.ignore_case, meta_dict=self.meta_dict
            )
            yield from completer.get_completions(document, complete_event)


def get_cmd_node(node,
                 cmdline):
    """
    Recursively traverse the command line tree to get to the matching node

    :return: last matching CLITree node, remaining tokens
    """
    # No more subcommands to parse, return node
    if cmdline == []:
        return node, []

    for child in node.children:
        if cmdline[0] == child.name:
            return get_cmd_node(child, cmdline[1:])

    # No matching child node
    return node, cmdline[:]


def exec_cmd(cmd_str, device_com):
    if cmd_str == '':
        return

    # look for alternate exit
    if cmd_str in ["quit", "q", "e"]:
        cmd_str = 'exit'

    # look for alternate comments
    if cmd_str[0] in ";#%":
        cmd_str = 'rem ' + cmd_str[1:].lstrip()

    # parse cmd
    argv = cmd_str.split()

    tree_node, arg_list = get_cmd_node(root, argv)
    if not tree_node.cls:
        # Found tree node is a group without an implementation, print children
        print("".ljust(18, "-") + "".ljust(10) + "".ljust(30, "-"))
        for child in tree_node.children:
            cmd_title = color_string((CG, child.name))
            if not child.cls:
                help_line = (f" - {cmd_title}".ljust(37)) + f"{{ {child.help_text}... }}"
            else:
                help_line = (f" - {cmd_title}".ljust(37)) + f"{child.help_text}"
            print(help_line)
        return

    unit = tree_node.cls()
    unit.device_com = device_com
    args_parse_result = unit.args_parser()

    assert args_parse_result is not None
    args: argparse.ArgumentParser = args_parse_result
    args.prog = tree_node.fullname
    try:
        args_parse_result = args.parse_args(arg_list)
        if args.help_requested:
            return
    except ArgsParserError as e:
        args.print_help()
        print(color_string((CY, str(e).strip())))
        return
    except ParserExitIntercept:
        # don't exit process.
        return
    try:
        # before process cmd, we need to do something...
        if not unit.before_exec(args_parse_result):
            return

        # start process cmd, delay error to call after_exec firstly
        error = None
        try:
            unit.on_exec(args_parse_result)
        except Exception as e:
            error = e
        unit.after_exec(args_parse_result)
        if error is not None:
            raise error

    except (UnexpectedResponseError, ArgsParserError) as e:
        print(color_string((CR, str(e))))
    except Exception:
        print(f"CLI exception: {color_string((CR, traceback.format_exc()))}")


def check_tools():
    bin_dir = Path.cwd() / "bin"
    missing_tools = []

    for tool in ("staticnested", "nested", "darkside", "mfkey32v2"):
        if any(bin_dir.glob(f"{tool}*")):
            continue
        else:
            missing_tools.append(tool)

    if missing_tools:
        missing_tool_str = ", ".join(missing_tools)
        warn_str = f"Warning, {missing_tool_str} not found. Corresponding commands will not work as intended"
        print(color_string((CR, warn_str)))


def run():
    # import pdb; pdb.set_trace()
    hist_file = Path.home() / ".chameleon_history"
    device_com = ChameleonCom()
    completer = CustomNestedCompleter.from_clitree(root)
    session = PromptSession(completer=completer, history=FileHistory(hist_file))
    colorama.init(autoreset=True)
    check_tools()
    print(color_string((CY, BANNER)))

    cmd_strs = []
    while True:
        if device_com.isOpen():
            status = color_string((CG, 'USB'))
        else:
            status = color_string((CR, 'Offline'))

        prompt = ANSI(f"[{status}] chameleon --> ")

        if cmd_strs:
            cmd_str = cmd_strs.pop(0)
        else:
            # wait user input
            try:
                cmd_str = session.prompt(prompt).strip()
                cmd_strs = cmd_str.replace("\r\n", "\n").replace("\r", "\n").split("\n")
                cmd_str = cmd_strs.pop(0)
            except EOFError:
                cmd_str = 'exit'
            except KeyboardInterrupt:
                cmd_str = 'exit'
        exec_cmd(cmd_str, device_com)

if __name__ == '__main__': run()

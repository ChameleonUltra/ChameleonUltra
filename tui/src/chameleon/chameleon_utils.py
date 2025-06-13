import argparse

from collections.abc import Callable
from functools import wraps
from pathlib import Path

# once Python3.10 is mainstream, we can replace Union[str, None] by str | None
from typing import Any

import colorama

from chameleon.chameleon_enum import Status


# Colorama shorthands
CR = colorama.Fore.RED
CG = colorama.Fore.GREEN
CB = colorama.Fore.BLUE
CC = colorama.Fore.CYAN
CY = colorama.Fore.YELLOW
CM = colorama.Fore.MAGENTA
C0 = colorama.Style.RESET_ALL


class ArgsParserError(Exception):
    pass


class ParserExitIntercept(Exception):
    pass


class UnexpectedResponseError(Exception):
    """
    Unexpected response exception
    """


class ArgumentParserNoExit(argparse.ArgumentParser):
    """
        If arg ArgumentParser parse error, we can't exit process,
        we must raise exception to stop parse
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.add_help = False
        self.description = "Please enter correct parameters"
        self.help_requested = False

    def exit(self, status: int = 0, message: str | None = None):
        if message:
            raise ParserExitIntercept(message)

    def error(self, message: str):
        args = {'prog': self.prog, 'message': message}
        raise ArgsParserError('%(prog)s: error: %(message)s\n' % args)

    def print_help(self):
        """
        Colorize argparse help
        """
        print("-" * 80)
        print(color_string((CR, self.prog)))
        lines = self.format_help().splitlines()
        usage = lines[:lines.index('')]
        assert usage[0].startswith('usage:')
        usage[0] = usage[0].replace('usage:', f'{color_string((CG, "usage:"))}\n ')
        usage[0] = usage[0].replace(self.prog, color_string((CR, self.prog)))
        usage = [usage[0]] + [x[4:] for x in usage[1:]] + ['']
        lines = lines[lines.index('')+1:]
        desc = lines[:lines.index('')]
        print(color_string((CC, "\n".join(desc))))
        print('\n'.join(usage))
        lines = lines[lines.index('')+1:]
        if '' in lines:
            options = lines[:lines.index('')]
            lines = lines[lines.index('')+1:]
        else:
            options = lines
            lines = []
        if len(options) > 0 and options[0].strip() == 'positional arguments:':
            positional_args = options
            positional_args[0] = positional_args[0].replace('positional arguments:', color_string((CG, "positional arguments:")))
            if len(positional_args) > 1:
                positional_args.append('')
            print('\n'.join(positional_args))
            if '' in lines:
                options = lines[:lines.index('')]
                lines = lines[lines.index('')+1:]
            else:
                options = lines
                lines = []
        if len(options) > 0:
            # 2 variants depending on Python version(?)
            assert options[0].strip() in ['options:', 'optional arguments:']
            options[0] = options[0].replace('options:', color_string((CG, "options:")))
            options[0] = options[0].replace('optional arguments:', color_string((CG, "optional arguments:")))
            if len(options) > 1:
                options.append('')
            print('\n'.join(options))
        if len(lines) > 0:
            lines[0] = color_string((CG, lines[0]))
            print('\n'.join(lines))
        print('')
        self.help_requested = True


default_cwd = Path.cwd() / Path(__file__).with_name("bin")

def print_mem_dump(bindata, blocksize):

    hexadecimal_len = blocksize*3+1
    ascii_len = blocksize+1
    print(f"[=] ----+{hexadecimal_len*'-'}+{ascii_len*'-'}")
    print(f"[=] blk | data{(hexadecimal_len-5)*' '}| ascii")
    print(f"[=] ----+{hexadecimal_len*'-'}+{ascii_len*'-'}")

    blocks = [bindata[i:i+blocksize] for i in range(0, len(bindata), blocksize)]
    blk_index = 1
    for b in blocks:
        hexstr = ' '.join(b.hex()[i:i+2] for i in range(0, len(b.hex()), 2))
        asciistr = ''.join([chr(b[i]) if (b[i] > 31 and b[i] < 127) else '.' for i in range(0,len(b),1)])
        print(f"[=] {blk_index:3} | {hexstr.upper()} | {asciistr} ")
        blk_index += 1

def expect_response(accepted_responses: int | list[int]) -> Callable[..., Any]:
    """
    Decorator for wrapping a Chameleon CMD function to check its response
    for expected return codes and throwing an exception otherwise
    """
    if isinstance(accepted_responses, int):
        accepted_responses = [accepted_responses]

    def decorator(func):
        @wraps(func)
        def error_throwing_func(*args, **kwargs):
            ret = func(*args, **kwargs)
            if ret.status not in accepted_responses:
                try:
                    status_string = str(Status(ret.status))
                except ValueError:
                    status_string = f"Unexpected response and unknown status {ret.status}"
                raise UnexpectedResponseError(status_string)

            return ret.parsed

        return error_throwing_func

    return decorator


def color_string(*args):
    result = []
    for arg in args:
        result.append(f"{arg[0]}{arg[1]}")
    result.append(C0)
    return "".join(result)

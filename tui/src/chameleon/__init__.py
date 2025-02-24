import sys
import colorama

from chameleon.chameleon_cli_main import ChameleonCLI
from chameleon.chameleon_cli_unit import check_tools


def main():
    if sys.version_info < (3, 9):
        raise Exception("This script requires at least Python 3.9")
    colorama.init(autoreset=True)
    check_tools()
    ChameleonCLI().startCLI()

from pathlib import Path

from pyapp.app import CliApplication, argument

APP = CliApplication()


@APP.command
@argument("PATH", type=Path, help_text="Location of CA")
def init(opts):
    """
    Initialise CA
    """
    from .actions import init_ca
    init_ca(opts.PATH)


def main():
    APP.dispatch()


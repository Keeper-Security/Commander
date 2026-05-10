import re
from contextlib import redirect_stdout
from io import StringIO

from keepercommander.commands.utils import HelpCommand
from keepercommander.params import KeeperParams


def test_migrate_not_in_default_help():
    """B1 regression: migrate must not appear in --help for non-enterprise users."""
    params = KeeperParams()
    params.enterprise = None
    params.enterprise_ec_key = None

    output = StringIO()
    with redirect_stdout(output):
        HelpCommand().execute(params)

    rendered_help = re.sub(r"\x1b\[[0-9;]*m", "", output.getvalue())
    assert not re.search(r"(?m)^\s*migrate(?:\s|$)", rendered_help)

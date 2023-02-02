import utilities_common.cli as clicommon
from clear.main import run_command, AliasedGroup, cli

#
# 'nat' group ("clear nat ...")
#

@cli.group(cls=AliasedGroup)
def nat():
    """Clear the nat info"""
    pass

# 'statistics' subcommand ("clear nat statistics")
@nat.command()
def statistics():
    """ Clear all NAT statistics """

    cmd = "natclear -s"
    run_command(cmd)

# 'translations' subcommand ("clear nat translations")
@nat.command()
def translations():
    """ Clear all NAT translations """

    cmd = "natclear -t"
    run_command(cmd)

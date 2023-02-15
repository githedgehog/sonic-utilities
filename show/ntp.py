import click

from tabulate import tabulate
from show.main import is_mgmt_vrf_enabled, run_command


#
# 'ntp' command ("show ntp")
#
@click.command()
@click.pass_context
@click.option('--verbose', is_flag=True, help="Enable verbose output")
def ntp(ctx, verbose):
    """Show NTP information"""
    from pkg_resources import parse_version
    ntpstat_cmd = "ntpstat"
    ntpcmd = "ntpq -p -n"
    if is_mgmt_vrf_enabled(ctx) is True:
        #ManagementVRF is enabled. Call ntpq using "ip vrf exec" or cgexec based on linux version
        os_info =  os.uname()
        release = os_info[2].split('-')
        if parse_version(release[0]) > parse_version("4.9.0"):
            ntpstat_cmd = "sudo ip vrf exec mgmt ntpstat"
            ntpcmd = "sudo ip vrf exec mgmt ntpq -p -n"
        else:
            ntpstat_cmd = "sudo cgexec -g l3mdev:mgmt ntpstat"
            ntpcmd = "sudo cgexec -g l3mdev:mgmt ntpq -p -n"

    run_command(ntpstat_cmd, display_cmd=verbose)
    run_command(ntpcmd, display_cmd=verbose)


#
# 'ntp' subcommand ("show runningconfiguration ntp")
#
@click.command(name='ntp')
@click.option('--verbose', is_flag=True, help="Enable verbose output")
def run_cfg_ntp(verbose):
    """Show NTP running configuration"""
    ntp_servers = []
    ntp_dict = {}
    with open("/etc/ntp.conf") as ntp_file:
        data = ntp_file.readlines()
    for line in data:
        if line.startswith("server "):
            ntp_server = line.split(" ")[1]
            ntp_servers.append(ntp_server)
    ntp_dict['NTP Servers'] = ntp_servers
    print(tabulate(ntp_dict, headers=list(ntp_dict.keys()), tablefmt="simple", stralign='left', missingval=""))

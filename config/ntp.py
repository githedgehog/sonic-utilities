import click
import utilities_common.cli as clicommon

from swsscommon.swsscommon import ConfigDBConnector


#
# 'ntp' group ('config ntp ...')
#
@click.group(cls=clicommon.AbbreviationGroup)
@click.pass_context
def ntp(ctx):
    """NTP server configuration tasks"""
    config_db = ConfigDBConnector()
    config_db.connect()
    ctx.obj = {'db': config_db}

@ntp.command('add')
@click.argument('ntp_ip_address', metavar='<ntp_ip_address>', required=True)
@click.pass_context
def add_ntp_server(ctx, ntp_ip_address):
    """ Add NTP server IP """
    if not clicommon.is_ipaddress(ntp_ip_address):
        ctx.fail('Invalid ip address')
    db = ctx.obj['db']
    ntp_servers = db.get_table("NTP_SERVER")
    if ntp_ip_address in ntp_servers:
        click.echo("NTP server {} is already configured".format(ntp_ip_address))
        return
    else:
        db.set_entry('NTP_SERVER', ntp_ip_address, {'NULL': 'NULL'})
        click.echo("NTP server {} added to configuration".format(ntp_ip_address))
        try:
            click.echo("Restarting ntp-config service...")
            clicommon.run_command("systemctl restart ntp-config", display_cmd=False)
        except SystemExit as e:
            ctx.fail("Restart service ntp-config failed with error {}".format(e))

@ntp.command('del')
@click.argument('ntp_ip_address', metavar='<ntp_ip_address>', required=True)
@click.pass_context
def del_ntp_server(ctx, ntp_ip_address):
    """ Delete NTP server IP """
    if not clicommon.is_ipaddress(ntp_ip_address):
        ctx.fail('Invalid IP address')
    db = ctx.obj['db']
    ntp_servers = db.get_table("NTP_SERVER")
    if ntp_ip_address in ntp_servers:
        db.set_entry('NTP_SERVER', '{}'.format(ntp_ip_address), None)
        click.echo("NTP server {} removed from configuration".format(ntp_ip_address))
    else:
        ctx.fail("NTP server {} is not configured.".format(ntp_ip_address))
    try:
        click.echo("Restarting ntp-config service...")
        clicommon.run_command("systemctl restart ntp-config", display_cmd=False)
    except SystemExit as e:
        ctx.fail("Restart service ntp-config failed with error {}".format(e))

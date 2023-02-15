import click
import utilities_common.cli as clicommon

from tabulate import tabulate
from natsort import natsorted
from swsscommon.swsscommon import ConfigDBConnector


#
# 'snmpagentaddress' group ("show snmpagentaddress ...")
#
@click.group('snmpagentaddress', invoke_without_command=True)
@click.pass_context
def snmpagentaddress (ctx):
    """Show SNMP agent listening IP address configuration"""
    config_db = ConfigDBConnector()
    config_db.connect()
    agenttable = config_db.get_table('SNMP_AGENT_ADDRESS_CONFIG')

    header = ['ListenIP', 'ListenPort', 'ListenVrf']
    body = []
    for agent in agenttable:
        body.append([agent[0], agent[1], agent[2]])
    click.echo(tabulate(body, header))


#
# 'snmptrap' group ("show snmptrap ...")
#
@click.group('snmptrap', invoke_without_command=True)
@click.pass_context
def snmptrap (ctx):
    """Show SNMP agent Trap server configuration"""
    config_db = ConfigDBConnector()
    config_db.connect()
    traptable = config_db.get_table('SNMP_TRAP_CONFIG')

    header = ['Version', 'TrapReceiverIP', 'Port', 'VRF', 'Community']
    body = []
    for row in traptable:
        if row == "v1TrapDest":
            ver=1
        elif row == "v2TrapDest":
            ver=2
        else:
            ver=3
        body.append([ver, traptable[row]['DestIp'], traptable[row]['DestPort'], traptable[row]['vrf'], traptable[row]['Community']])
    click.echo(tabulate(body, header))


#
# 'snmp' group ("show runningconfiguration snmp ...")
#
@click.group("snmp", invoke_without_command=True)
@clicommon.pass_db
@click.pass_context
def snmp(ctx, db):
    """Show SNMP running configuration"""
    if ctx.invoked_subcommand is None:
       show_run_snmp(db.cfgdb)


# ("show runningconfiguration snmp community")
@snmp.command('community')
@click.option('--json', 'json_output', required=False, is_flag=True, type=click.BOOL,
              help="Display the output in JSON format")
@clicommon.pass_db
def community(db, json_output):
    """show SNMP running configuration community"""
    snmp_comm_header = ["Community String", "Community Type"]
    snmp_comm_body = []
    snmp_comm_keys = db.cfgdb.get_table('SNMP_COMMUNITY')
    snmp_comm_strings = snmp_comm_keys.keys()
    if json_output:
        click.echo(snmp_comm_keys)
    else:
        for line in snmp_comm_strings:
            comm_string = line
            comm_string_type = snmp_comm_keys[line]['TYPE']
            snmp_comm_body.append([comm_string, comm_string_type])
        click.echo(tabulate(natsorted(snmp_comm_body), snmp_comm_header))


# ("show runningconfiguration snmp contact")
@snmp.command('contact')
@click.option('--json', 'json_output', required=False, is_flag=True, type=click.BOOL,
              help="Display the output in JSON format")
@clicommon.pass_db
def contact(db, json_output):
    """show SNMP running configuration contact"""
    snmp = db.cfgdb.get_table('SNMP')
    snmp_header = ["Contact", "Contact Email"]
    snmp_body = []
    if json_output:
        try:
            if snmp['CONTACT']:
                click.echo(snmp['CONTACT'])
        except KeyError:
            snmp['CONTACT'] = {}
            click.echo(snmp['CONTACT'])
    else:
        try:
            if snmp['CONTACT']:
                snmp_contact = list(snmp['CONTACT'].keys())
                snmp_contact_email = [snmp['CONTACT'][snmp_contact[0]]]
                snmp_body.append([snmp_contact[0], snmp_contact_email[0]])
        except KeyError:
            snmp['CONTACT'] = ''
        click.echo(tabulate(snmp_body, snmp_header))


# ("show runningconfiguration snmp location")
@snmp.command('location')
@click.option('--json', 'json_output', required=False, is_flag=True, type=click.BOOL,
              help="Display the output in JSON format")
@clicommon.pass_db
def location(db, json_output):
    """show SNMP running configuration location"""
    snmp = db.cfgdb.get_table('SNMP')
    snmp_header = ["Location"]
    snmp_body = []
    if json_output:
        try:
            if snmp['LOCATION']:
                click.echo(snmp['LOCATION'])
        except KeyError:
            snmp['LOCATION'] = {}
            click.echo(snmp['LOCATION'])
    else:
        try:
            if snmp['LOCATION']:
                snmp_location = [snmp['LOCATION']['Location']]
                snmp_body.append(snmp_location)
        except KeyError:
            snmp['LOCATION'] = ''
        click.echo(tabulate(snmp_body, snmp_header))


# ("show runningconfiguration snmp user")
@snmp.command('user')
@click.option('--json', 'json_output', required=False, is_flag=True, type=click.BOOL,
              help="Display the output in JSON format")
@clicommon.pass_db
def users(db, json_output):
    """show SNMP running configuration user"""
    snmp_users = db.cfgdb.get_table('SNMP_USER')
    snmp_user_header = ['User', "Permission Type", "Type", "Auth Type", "Auth Password", "Encryption Type",
                        "Encryption Password"]
    snmp_user_body = []
    if json_output:
        click.echo(snmp_users)
    else:
        for snmp_user, snmp_user_value in snmp_users.items():
            snmp_user_permissions_type = snmp_users[snmp_user].get('SNMP_USER_PERMISSION', 'Null')
            snmp_user_auth_type = snmp_users[snmp_user].get('SNMP_USER_AUTH_TYPE', 'Null')
            snmp_user_auth_password = snmp_users[snmp_user].get('SNMP_USER_AUTH_PASSWORD', 'Null')
            snmp_user_encryption_type = snmp_users[snmp_user].get('SNMP_USER_ENCRYPTION_TYPE', 'Null')
            snmp_user_encryption_password = snmp_users[snmp_user].get('SNMP_USER_ENCRYPTION_PASSWORD', 'Null')
            snmp_user_type = snmp_users[snmp_user].get('SNMP_USER_TYPE', 'Null')
            snmp_user_body.append([snmp_user, snmp_user_permissions_type, snmp_user_type, snmp_user_auth_type,
                                   snmp_user_auth_password, snmp_user_encryption_type, snmp_user_encryption_password])
        click.echo(tabulate(natsorted(snmp_user_body), snmp_user_header))


# ("show runningconfiguration snmp")
@clicommon.pass_db
def show_run_snmp(db, ctx):
    snmp_contact_location_table = db.cfgdb.get_table('SNMP')
    snmp_comm_table = db.cfgdb.get_table('SNMP_COMMUNITY')
    snmp_users = db.cfgdb.get_table('SNMP_USER')
    snmp_location_header = ["Location"]
    snmp_location_body = []
    snmp_contact_header = ["SNMP_CONTACT", "SNMP_CONTACT_EMAIL"]
    snmp_contact_body = []
    snmp_comm_header = ["Community String", "Community Type"]
    snmp_comm_body = []
    snmp_user_header = ['User', "Permission Type", "Type", "Auth Type", "Auth Password", "Encryption Type",
                        "Encryption Password"]
    snmp_user_body = []
    try:
        if snmp_contact_location_table['LOCATION']:
            snmp_location = [snmp_contact_location_table['LOCATION']['Location']]
            snmp_location_body.append(snmp_location)
    except KeyError:
        snmp_contact_location_table['LOCATION'] = ''
    click.echo(tabulate(snmp_location_body, snmp_location_header))
    click.echo("\n")
    try:
        if snmp_contact_location_table['CONTACT']:
            snmp_contact = list(snmp_contact_location_table['CONTACT'].keys())
            snmp_contact_email = [snmp_contact_location_table['CONTACT'][snmp_contact[0]]]
            snmp_contact_body.append([snmp_contact[0], snmp_contact_email[0]])
    except KeyError:
        snmp_contact_location_table['CONTACT'] = ''
    click.echo(tabulate(snmp_contact_body, snmp_contact_header))
    click.echo("\n")
    snmp_comm_strings = snmp_comm_table.keys()
    for line in snmp_comm_strings:
        comm_string = line
        comm_string_type = snmp_comm_table[line]['TYPE']
        snmp_comm_body.append([comm_string, comm_string_type])
    click.echo(tabulate(natsorted(snmp_comm_body), snmp_comm_header))
    click.echo("\n")
    for snmp_user, snmp_user_value in snmp_users.items():
        snmp_user_permissions_type = snmp_users[snmp_user].get('SNMP_USER_PERMISSION', 'Null')
        snmp_user_auth_type = snmp_users[snmp_user].get('SNMP_USER_AUTH_TYPE', 'Null')
        snmp_user_auth_password = snmp_users[snmp_user].get('SNMP_USER_AUTH_PASSWORD', 'Null')
        snmp_user_encryption_type = snmp_users[snmp_user].get('SNMP_USER_ENCRYPTION_TYPE', 'Null')
        snmp_user_encryption_password = snmp_users[snmp_user].get('SNMP_USER_ENCRYPTION_PASSWORD', 'Null')
        snmp_user_type = snmp_users[snmp_user].get('SNMP_USER_TYPE', 'Null')
        snmp_user_body.append([snmp_user, snmp_user_permissions_type, snmp_user_type, snmp_user_auth_type,
                               snmp_user_auth_password, snmp_user_encryption_type, snmp_user_encryption_password])
    click.echo(tabulate(natsorted(snmp_user_body), snmp_user_header))

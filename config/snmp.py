import os
import re
import sys
import click
import ipaddress
import netifaces
import utilities_common.cli as clicommon

from socket import AF_INET, AF_INET6
from swsscommon.swsscommon import ConfigDBConnector

#
# 'snmp' group ('config snmp ...')
#
@click.group(cls=clicommon.AbbreviationGroup, name='snmp')
@clicommon.pass_db
def snmp(db):
    """SNMP configuration tasks"""


@snmp.group(cls=clicommon.AbbreviationGroup)
@clicommon.pass_db
def community(db):
    pass


def is_valid_community_type(commstr_type):
    commstr_types = ['RO', 'RW']
    if commstr_type not in commstr_types:
        click.echo("Invalid community type.  Must be either RO or RW")
        return False
    return True


def is_valid_user_type(user_type):
    convert_user_type = {'noauthnopriv': 'noAuthNoPriv', 'authnopriv': 'AuthNoPriv', 'priv': 'Priv'}
    if user_type not in convert_user_type:
        message = ("Invalid user type.  Must be one of these one of these three "
                   "'noauthnopriv' or 'authnopriv' or 'priv'")
        click.echo(message)
        return False, message
    return True, convert_user_type[user_type]


def is_valid_auth_type(user_auth_type):
    user_auth_types = ['MD5', 'SHA', 'HMAC-SHA-2']
    if user_auth_type not in user_auth_types:
        click.echo("Invalid user authentication type. Must be one of these 'MD5', 'SHA', or 'HMAC-SHA-2'")
        return False
    return True


def is_valid_encrypt_type(encrypt_type):
    encrypt_types = ['DES', 'AES']
    if encrypt_type not in encrypt_types:
        click.echo("Invalid user encryption type.  Must be one of these two 'DES' or 'AES'")
        return False
    return True


def snmp_community_secret_check(snmp_secret):
    excluded_special_symbols = ['@', ":"]
    if len(snmp_secret) > 32:
        click.echo("SNMP community string length should be not be greater than 32")
        click.echo("SNMP community string should not have any of these special "
                   "symbols {}".format(excluded_special_symbols))
        click.echo("FAILED: SNMP community string length should be not be greater than 32")
        return False
    if any(char in excluded_special_symbols for char in snmp_secret):
        click.echo("SNMP community string length should be not be greater than 32")
        click.echo("SNMP community string should not have any of these special "
                   "symbols {}".format(excluded_special_symbols))
        click.echo("FAILED: SNMP community string should not have any of these "
                   "special symbols {}".format(excluded_special_symbols))
        return False
    return True


def snmp_username_check(snmp_username):
    excluded_special_symbols = ['@', ":"]
    if len(snmp_username) > 32:
        click.echo("SNMP user {} length should be not be greater than 32 characters".format(snmp_username))
        click.echo("SNMP community string should not have any of these special "
                   "symbols {}".format(excluded_special_symbols))
        click.echo("FAILED: SNMP user {} length should not be greater than 32 characters".format(snmp_username))
        return False
    if any(char in excluded_special_symbols for char in snmp_username):
        click.echo("SNMP user {} length should be not be greater than 32 characters".format(snmp_username))
        click.echo("SNMP community string should not have any of these special "
                   "symbols {}".format(excluded_special_symbols))
        click.echo("FAILED: SNMP user {} should not have any of these special "
                   "symbols {}".format(snmp_username, excluded_special_symbols))
        return False
    return True


def snmp_user_secret_check(snmp_secret):
    excluded_special_symbols = ['@', ":"]
    if len(snmp_secret) < 8:
        click.echo("SNMP user password length should be at least 8 characters")
        click.echo("SNMP user password length should be not be greater than 64")
        click.echo("SNMP user password should not have any of these special "
                   "symbols {}".format(excluded_special_symbols))
        click.echo("FAILED: SNMP user password length should be at least 8 characters")
        return False
    if len(snmp_secret) > 64:
        click.echo("SNMP user password length should be at least 8 characters")
        click.echo("SNMP user password length should be not be greater than 64")
        click.echo("SNMP user password should not have any of these special "
                   "symbols {}".format(excluded_special_symbols))
        click.echo("FAILED: SNMP user password length should be not be greater than 64")
        return False
    if any(char in excluded_special_symbols for char in snmp_secret):
        click.echo("SNMP user password length should be at least 8 characters")
        click.echo("SNMP user password length should be not be greater than 64")
        click.echo("SNMP user password should not have any of these special "
                   "symbols {}".format(excluded_special_symbols))
        click.echo("FAILED: SNMP user password should not have any of these special "
                   "symbols {}".format(excluded_special_symbols))
        return False
    return True


@community.command('add')
@click.argument('community', metavar='<snmp_community>', required=True)
@click.argument('string_type', metavar='<RO|RW>', required=True)
@clicommon.pass_db
def add_community(db, community, string_type):
    """ Add snmp community string"""
    string_type = string_type.upper()
    if not is_valid_community_type(string_type):
        sys.exit(1)
    if not snmp_community_secret_check(community):
        sys.exit(2)
    snmp_communities = db.cfgdb.get_table("SNMP_COMMUNITY")
    if community in snmp_communities:
        click.echo("SNMP community {} is already configured".format(community))
        sys.exit(3)
    db.cfgdb.set_entry('SNMP_COMMUNITY', community, {'TYPE': string_type})
    click.echo("SNMP community {} added to configuration".format(community))
    try:
        click.echo("Restarting SNMP service...")
        clicommon.run_command("systemctl reset-failed snmp.service", display_cmd=False)
        clicommon.run_command("systemctl restart snmp.service", display_cmd=False)
    except SystemExit as e:
        click.echo("Restart service snmp failed with error {}".format(e))
        raise click.Abort()


@community.command('del')
@click.argument('community', metavar='<snmp_community>', required=True)
@clicommon.pass_db
def del_community(db, community):
    """ Delete snmp community string"""
    snmp_communities = db.cfgdb.get_table("SNMP_COMMUNITY")
    if community not in snmp_communities:
        click.echo("SNMP community {} is not configured".format(community))
        sys.exit(1)
    else:
        db.cfgdb.set_entry('SNMP_COMMUNITY', community, None)
        click.echo("SNMP community {} removed from configuration".format(community))
        try:
            click.echo("Restarting SNMP service...")
            clicommon.run_command("systemctl reset-failed snmp.service", display_cmd=False)
            clicommon.run_command("systemctl restart snmp.service", display_cmd=False)
        except SystemExit as e:
            click.echo("Restart service snmp failed with error {}".format(e))
            raise click.Abort()


@community.command('replace')
@click.argument('current_community', metavar='<current_community_string>', required=True)
@click.argument('new_community', metavar='<new_community_string>', required=True)
@clicommon.pass_db
def replace_community(db, current_community, new_community):
    """ Replace snmp community string"""
    snmp_communities = db.cfgdb.get_table("SNMP_COMMUNITY")
    if not current_community in snmp_communities:
        click.echo("Current SNMP community {} is not configured".format(current_community))
        sys.exit(1)
    if not snmp_community_secret_check(new_community):
        sys.exit(2)
    elif new_community in snmp_communities:
        click.echo("New SNMP community {} to replace current SNMP community {} already "
                   "configured".format(new_community, current_community))
        sys.exit(3)
    else:
        string_type = snmp_communities[current_community]['TYPE']
        db.cfgdb.set_entry('SNMP_COMMUNITY', new_community, {'TYPE': string_type})
        click.echo("SNMP community {} added to configuration".format(new_community))
        db.cfgdb.set_entry('SNMP_COMMUNITY', current_community, None)
        click.echo('SNMP community {} replace community {}'.format(new_community, current_community))
        try:
            click.echo("Restarting SNMP service...")
            clicommon.run_command("systemctl reset-failed snmp.service", display_cmd=False)
            clicommon.run_command("systemctl restart snmp.service", display_cmd=False)
        except SystemExit as e:
            click.echo("Restart service snmp failed with error {}".format(e))
            raise click.Abort()


@snmp.group(cls=clicommon.AbbreviationGroup)
@clicommon.pass_db
def contact(db):
    pass


def is_valid_email(email):
    return bool(re.search(r"^[\w\.\+\-]+\@[\w]+\.[a-z]{2,3}$", email))


@contact.command('add')
@click.argument('contact', metavar='<contact_name>', required=True)
@click.argument('contact_email', metavar='<contact_email>', required=True)
@clicommon.pass_db
def add_contact(db, contact, contact_email):
    """ Add snmp contact name and email """
    snmp = db.cfgdb.get_table("SNMP")
    try:
        if snmp['CONTACT']:
            click.echo("Contact already exists.  Use sudo config snmp contact modify instead")
            sys.exit(1)
        else:
            db.cfgdb.set_entry('SNMP', 'CONTACT', {contact: contact_email})
            click.echo("Contact name {} and contact email {} have been added to "
                       "configuration".format(contact, contact_email))
            try:
                click.echo("Restarting SNMP service...")
                clicommon.run_command("systemctl reset-failed snmp.service", display_cmd=False)
                clicommon.run_command("systemctl restart snmp.service", display_cmd=False)
            except SystemExit as e:
                click.echo("Restart service snmp failed with error {}".format(e))
                raise click.Abort()
    except KeyError:
        if "CONTACT" not in snmp.keys():
            if not is_valid_email(contact_email):
                click.echo("Contact email {} is not valid".format(contact_email))
                sys.exit(2)
            db.cfgdb.set_entry('SNMP', 'CONTACT', {contact: contact_email})
            click.echo("Contact name {} and contact email {} have been added to "
                       "configuration".format(contact, contact_email))
            try:
                click.echo("Restarting SNMP service...")
                clicommon.run_command("systemctl reset-failed snmp.service", display_cmd=False)
                clicommon.run_command("systemctl restart snmp.service", display_cmd=False)
            except SystemExit as e:
                click.echo("Restart service snmp failed with error {}".format(e))
                raise click.Abort()


@contact.command('del')
@click.argument('contact', metavar='<contact_name>', required=True)
@clicommon.pass_db
def del_contact(db, contact):
    """ Delete snmp contact name and email """
    snmp = db.cfgdb.get_table("SNMP")
    try:
        if not contact in (list(snmp['CONTACT'].keys()))[0]:
            click.echo("SNMP contact {} is not configured".format(contact))
            sys.exit(1)
        else:
            db.cfgdb.set_entry('SNMP', 'CONTACT', None)
            click.echo("SNMP contact {} removed from configuration".format(contact))
            try:
                click.echo("Restarting SNMP service...")
                clicommon.run_command("systemctl reset-failed snmp.service", display_cmd=False)
                clicommon.run_command("systemctl restart snmp.service", display_cmd=False)
            except SystemExit as e:
                click.echo("Restart service snmp failed with error {}".format(e))
                raise click.Abort()
    except KeyError:
        if "CONTACT" not in snmp.keys():
            click.echo("Contact name {} is not configured".format(contact))
            sys.exit(2)


@contact.command('modify')
@click.argument('contact', metavar='<contact>', required=True)
@click.argument('contact_email', metavar='<contact email>', required=True)
@clicommon.pass_db
def modify_contact(db, contact, contact_email):
    """ Modify snmp contact"""
    snmp = db.cfgdb.get_table("SNMP")
    try:
        current_snmp_contact_name = (list(snmp['CONTACT'].keys()))[0]
        if current_snmp_contact_name == contact:
            current_snmp_contact_email = snmp['CONTACT'][contact]
        else:
            current_snmp_contact_email = ''
        if contact == current_snmp_contact_name and contact_email == current_snmp_contact_email:
            click.echo("SNMP contact {} {} already exists".format(contact, contact_email))
            sys.exit(1)
        elif contact == current_snmp_contact_name and contact_email != current_snmp_contact_email:
            if not is_valid_email(contact_email):
                click.echo("Contact email {} is not valid".format(contact_email))
                sys.exit(2)
            db.cfgdb.mod_entry('SNMP', 'CONTACT', {contact: contact_email})
            click.echo("SNMP contact {} email updated to {}".format(contact, contact_email))
            try:
                click.echo("Restarting SNMP service...")
                clicommon.run_command("systemctl reset-failed snmp.service", display_cmd=False)
                clicommon.run_command("systemctl restart snmp.service", display_cmd=False)
            except SystemExit as e:
                click.echo("Restart service snmp failed with error {}".format(e))
                raise click.Abort()
        else:
            if not is_valid_email(contact_email):
                click.echo("Contact email {} is not valid".format(contact_email))
                sys.exit(2)
            db.cfgdb.set_entry('SNMP', 'CONTACT', None)
            db.cfgdb.set_entry('SNMP', 'CONTACT', {contact: contact_email})
            click.echo("SNMP contact {} and contact email {} updated".format(contact, contact_email))
            try:
                click.echo("Restarting SNMP service...")
                clicommon.run_command("systemctl reset-failed snmp.service", display_cmd=False)
                clicommon.run_command("systemctl restart snmp.service", display_cmd=False)
            except SystemExit as e:
                click.echo("Restart service snmp failed with error {}".format(e))
                raise click.Abort()
    except KeyError:
        if "CONTACT" not in snmp.keys():
            click.echo("Contact name {} is not configured".format(contact))
            sys.exit(3)


@snmp.group(cls=clicommon.AbbreviationGroup)
@clicommon.pass_db
def location(db):
    pass


@location.command('add')
@click.argument('location', metavar='<location>', required=True, nargs=-1)
@clicommon.pass_db
def add_location(db, location):
    """ Add snmp location"""
    if isinstance(location, tuple):
        location = " ".join(location)
    elif isinstance(location, list):
        location = " ".join(location)
    snmp = db.cfgdb.get_table("SNMP")
    try:
        if snmp['LOCATION']:
            click.echo("Location already exists")
            sys.exit(1)
    except KeyError:
        if "LOCATION" not in snmp.keys():
            db.cfgdb.set_entry('SNMP', 'LOCATION', {'Location': location})
            click.echo("SNMP Location {} has been added to configuration".format(location))
            try:
                click.echo("Restarting SNMP service...")
                clicommon.run_command("systemctl reset-failed snmp.service", display_cmd=False)
                clicommon.run_command("systemctl restart snmp.service", display_cmd=False)
            except SystemExit as e:
                click.echo("Restart service snmp failed with error {}".format(e))
                raise click.Abort()


@location.command('del')
@click.argument('location', metavar='<location>', required=True, nargs=-1)
@clicommon.pass_db
def delete_location(db, location):
    """ Delete snmp location"""
    if isinstance(location, tuple):
        location = " ".join(location)
    elif isinstance(location, list):
        location = " ".join(location)
    snmp = db.cfgdb.get_table("SNMP")
    try:
        if location == snmp['LOCATION']['Location']:
            db.cfgdb.set_entry('SNMP', 'LOCATION', None)
            click.echo("SNMP Location {} removed from configuration".format(location))
            try:
                click.echo("Restarting SNMP service...")
                clicommon.run_command("systemctl reset-failed snmp.service", display_cmd=False)
                clicommon.run_command("systemctl restart snmp.service", display_cmd=False)
            except SystemExit as e:
                click.echo("Restart service snmp failed with error {}".format(e))
                raise click.Abort()
        else:
            click.echo("SNMP Location {} does not exist.  The location is {}".format(location, snmp['LOCATION']['Location']))
            sys.exit(1)
    except KeyError:
        if "LOCATION" not in snmp.keys():
            click.echo("SNMP Location {} is not configured".format(location))
            sys.exit(2)


@location.command('modify')
@click.argument('location', metavar='<location>', required=True, nargs=-1)
@clicommon.pass_db
def modify_location(db, location):
    """ Modify snmp location"""
    if isinstance(location, tuple):
        location = " ".join(location)
    elif isinstance(location, list):
        location = " ".join(location)
    snmp = db.cfgdb.get_table("SNMP")
    try:
        snmp_location = snmp['LOCATION']['Location']
        if location in snmp_location:
            click.echo("SNMP location {} already exists".format(location))
            sys.exit(1)
        else:
            db.cfgdb.mod_entry('SNMP', 'LOCATION', {'Location': location})
            click.echo("SNMP location {} modified in configuration".format(location))
            try:
                click.echo("Restarting SNMP service...")
                clicommon.run_command("systemctl reset-failed snmp.service", display_cmd=False)
                clicommon.run_command("systemctl restart snmp.service", display_cmd=False)
            except SystemExit as e:
                click.echo("Restart service snmp failed with error {}".format(e))
                raise click.Abort()
    except KeyError:
        click.echo("Cannot modify SNMP Location.  You must use 'config snmp location add command <snmp_location>'")
        sys.exit(2)


from enum import IntEnum
class SnmpUserError(IntEnum):
    NameCheckFailure = 1
    TypeNoAuthNoPrivOrAuthNoPrivOrPrivCheckFailure = 2
    RoRwCheckFailure = 3
    NoAuthNoPrivHasAuthType = 4
    AuthTypeMd5OrShaOrHmacsha2IsMissing = 5
    AuthTypeMd5OrShaOrHmacsha2Failure = 6
    AuthPasswordMissing = 7
    AuthPasswordFailsComplexityRequirements = 8
    EncryptPasswordNotAllowedWithAuthNoPriv = 9
    EncryptTypeDesOrAesIsMissing = 10
    EncryptTypeFailsComplexityRequirements = 11
    EncryptPasswordMissingFailure = 12
    EncryptPasswordFailsComplexityRequirements = 13
    UserAlreadyConfigured = 14


@snmp.group(cls=clicommon.AbbreviationGroup)
@clicommon.pass_db
def user(db):
    pass


@user.command('add')
@click.argument('user', metavar='<snmp_user>', required=True)
@click.argument('user_type', metavar='<noAuthNoPriv|AuthNoPriv|Priv>', required=True)
@click.argument('user_permission_type', metavar='<RO|RW>', required=True)
@click.argument('user_auth_type', metavar='<MD5|SHA|HMAC-SHA-2>', required=False)
@click.argument('user_auth_password', metavar='<auth_password>', required=False)
@click.argument('user_encrypt_type', metavar='<DES|AES>', required=False)
@click.argument('user_encrypt_password', metavar='<encrypt_password>', required=False)
@clicommon.pass_db
def add_user(db, user, user_type, user_permission_type, user_auth_type, user_auth_password, user_encrypt_type,
             user_encrypt_password):
    """ Add snmp user"""
    if not snmp_username_check(user):
        sys.exit(SnmpUserError.NameCheckFailure)
    user_type = user_type.lower()
    user_type_info = is_valid_user_type(user_type)
    if not user_type_info[0]:
        sys.exit(SnmpUserError.TypeNoAuthNoPrivOrAuthNoPrivOrPrivCheckFailure)
    user_type = user_type_info[1]
    user_permission_type = user_permission_type.upper()
    if not is_valid_community_type(user_permission_type):
        sys.exit(SnmpUserError.RoRwCheckFailure)
    if user_type == "noAuthNoPriv":
        if user_auth_type:
            click.echo("User auth type not used with 'noAuthNoPriv'.  Please use 'AuthNoPriv' or 'Priv' instead")
            sys.exit(SnmpUserError.NoAuthNoPrivHasAuthType)
    else:
        if not user_auth_type:
            click.echo("User auth type is missing.  Must be MD5, SHA, or HMAC-SHA-2")
            sys.exit(SnmpUserError.AuthTypeMd5OrShaOrHmacsha2IsMissing)
        if user_auth_type:
            user_auth_type = user_auth_type.upper()
            if not is_valid_auth_type(user_auth_type):
                sys.exit(SnmpUserError.AuthTypeMd5OrShaOrHmacsha2Failure)
            elif not user_auth_password:
                click.echo("User auth password is missing")
                sys.exit(SnmpUserError.AuthPasswordMissing)
            elif user_auth_password:
                if not snmp_user_secret_check(user_auth_password):
                    sys.exit(SnmpUserError.AuthPasswordFailsComplexityRequirements)
        if user_type == "AuthNoPriv":
            if user_encrypt_type:
                click.echo("User encrypt type not used with 'AuthNoPriv'.  Please use 'Priv' instead")
                sys.exit(SnmpUserError.EncryptPasswordNotAllowedWithAuthNoPriv)
        elif user_type == "Priv":
            if not user_encrypt_type:
                click.echo("User encrypt type is missing.  Must be DES or AES")
                sys.exit(SnmpUserError.EncryptTypeDesOrAesIsMissing)
            if user_encrypt_type:
                user_encrypt_type = user_encrypt_type.upper()
                if not is_valid_encrypt_type(user_encrypt_type):
                    sys.exit(SnmpUserError.EncryptTypeFailsComplexityRequirements)
                elif not user_encrypt_password:
                    click.echo("User encrypt password is missing")
                    sys.exit(SnmpUserError.EncryptPasswordMissingFailure)
                elif user_encrypt_password:
                    if not snmp_user_secret_check(user_encrypt_password):
                        sys.exit(SnmpUserError.EncryptPasswordFailsComplexityRequirements)
    snmp_users = db.cfgdb.get_table("SNMP_USER")
    if user in snmp_users.keys():
        click.echo("SNMP user {} is already configured".format(user))
        sys.exit(SnmpUserError.UserAlreadyConfigured)
    else:
        if not user_auth_type:
            user_auth_type = ''
        if not user_auth_password:
            user_auth_password = ''
        if not user_encrypt_type:
            user_encrypt_type = ''
        if not user_encrypt_password:
            user_encrypt_password = ''
        db.cfgdb.set_entry('SNMP_USER', user, {'SNMP_USER_TYPE': user_type,
                                               'SNMP_USER_PERMISSION': user_permission_type,
                                               'SNMP_USER_AUTH_TYPE': user_auth_type,
                                               'SNMP_USER_AUTH_PASSWORD': user_auth_password,
                                               'SNMP_USER_ENCRYPTION_TYPE': user_encrypt_type,
                                               'SNMP_USER_ENCRYPTION_PASSWORD': user_encrypt_password})
        click.echo("SNMP user {} added to configuration".format(user))
        try:
            click.echo("Restarting SNMP service...")
            clicommon.run_command("systemctl reset-failed snmp.service", display_cmd=False)
            clicommon.run_command("systemctl restart snmp.service", display_cmd=False)
        except SystemExit as e:
            click.echo("Restart service snmp failed with error {}".format(e))
            raise click.Abort()


@user.command('del')
@click.argument('user', metavar='<snmp_user>', required=True)
@clicommon.pass_db
def del_user(db, user):
    """ Del snmp user"""
    snmp_users = db.cfgdb.get_table("SNMP_USER")
    if user not in snmp_users:
        click.echo("SNMP user {} is not configured".format(user))
        sys.exit(1)
    else:
        db.cfgdb.set_entry('SNMP_USER', user, None)
        click.echo("SNMP user {} removed from configuration".format(user))
        try:
            click.echo("Restarting SNMP service...")
            clicommon.run_command("systemctl reset-failed snmp.service", display_cmd=False)
            clicommon.run_command("systemctl restart snmp.service", display_cmd=False)
        except SystemExit as e:
            click.echo("Restart service snmp failed with error {}".format(e))
            raise click.Abort()


#
# 'snmptrap' group ('config snmptrap ...')
#
@click.group(cls=clicommon.AbbreviationGroup)
@click.pass_context
def snmptrap(ctx):
    """SNMP Trap server configuration to send traps"""
    config_db = ConfigDBConnector()
    config_db.connect()
    ctx.obj = {'db': config_db}

@snmptrap.command('modify')
@click.argument('ver', metavar='<SNMP Version>', type=click.Choice(['1', '2', '3']), required=True)
@click.argument('serverip', metavar='<SNMP TRAP SERVER IP Address>', required=True)
@click.option('-p', '--port', help="SNMP Trap Server port, default 162", default="162")
@click.option('-v', '--vrf', help="VRF Name mgmt/DataVrfName/None", default="None")
@click.option('-c', '--comm', help="Community", default="public")
@click.pass_context
def modify_snmptrap_server(ctx, ver, serverip, port, vrf, comm):
    """Modify the SNMP Trap server configuration"""

    #SNMP_TRAP_CONFIG for each SNMP version
    config_db = ctx.obj['db']
    if ver == "1":
        #By default, v1TrapDest value in snmp.yml is "NotConfigured". Modify it.
        config_db.mod_entry('SNMP_TRAP_CONFIG', "v1TrapDest", {"DestIp": serverip, "DestPort": port, "vrf": vrf, "Community": comm})
    elif ver == "2":
        config_db.mod_entry('SNMP_TRAP_CONFIG', "v2TrapDest", {"DestIp": serverip, "DestPort": port, "vrf": vrf, "Community": comm})
    else:
        config_db.mod_entry('SNMP_TRAP_CONFIG', "v3TrapDest", {"DestIp": serverip, "DestPort": port, "vrf": vrf, "Community": comm})

    cmd="systemctl restart snmp"
    os.system (cmd)

@snmptrap.command('del')
@click.argument('ver', metavar='<SNMP Version>', type=click.Choice(['1', '2', '3']), required=True)
@click.pass_context
def delete_snmptrap_server(ctx, ver):
    """Delete the SNMP Trap server configuration"""

    config_db = ctx.obj['db']
    if ver == "1":
        config_db.mod_entry('SNMP_TRAP_CONFIG', "v1TrapDest", None)
    elif ver == "2":
        config_db.mod_entry('SNMP_TRAP_CONFIG', "v2TrapDest", None)
    else:
        config_db.mod_entry('SNMP_TRAP_CONFIG', "v3TrapDest", None)
    cmd="systemctl restart snmp"
    os.system (cmd)


#
# 'snmpagentaddress' group ('config snmpagentaddress ...')
#
@click.group(cls=clicommon.AbbreviationGroup)
@click.pass_context
def snmpagentaddress(ctx):
    """SNMP agent listening IP address, port, vrf configuration"""
    config_db = ConfigDBConnector()
    config_db.connect()
    ctx.obj = {'db': config_db}

ip_family = {4: AF_INET, 6: AF_INET6}

@snmpagentaddress.command('add')
@click.argument('agentip', metavar='<SNMP AGENT LISTENING IP Address>', required=True)
@click.option('-p', '--port', help="SNMP AGENT LISTENING PORT")
@click.option('-v', '--vrf', help="VRF Name mgmt/DataVrfName/None")
@click.pass_context
def add_snmp_agent_address(ctx, agentip, port, vrf):
    """Add the SNMP agent listening IP:Port%Vrf configuration"""

    #Construct SNMP_AGENT_ADDRESS_CONFIG table key in the format ip|<port>|<vrf>
    if not clicommon.is_ipaddress(agentip):
        click.echo("Invalid IP address")
        return False
    config_db = ctx.obj['db']
    if not vrf:
        entry = config_db.get_entry('MGMT_VRF_CONFIG', "vrf_global")
        if entry and entry['mgmtVrfEnabled'] == 'true' :
            click.echo("ManagementVRF is Enabled. Provide vrf.")
            return False
    found = 0
    ip = ipaddress.ip_address(agentip)
    for intf in netifaces.interfaces():
        ipaddresses = netifaces.ifaddresses(intf)
        if ip_family[ip.version] in ipaddresses:
            for ipaddr in ipaddresses[ip_family[ip.version]]:
                if agentip.lower() == ipaddr['addr'].lower():
                    found = 1
                    break
        if found == 1:
            break
    else:
        click.echo("IP address is not available")
        return

    key = agentip+'|'
    if port:
        key = key+port
    #snmpd does not start if we have two entries with same ip and port.
    key1 = "SNMP_AGENT_ADDRESS_CONFIG|" + key + '*'
    entry = config_db.get_keys(key1)
    if entry:
        ip_port = agentip + ":" + port
        click.echo("entry with {} already exists ".format(ip_port))
        return
    key = key+'|'
    if vrf:
        key = key+vrf
    config_db.set_entry('SNMP_AGENT_ADDRESS_CONFIG', key, {})

    #Restarting the SNMP service will regenerate snmpd.conf and rerun snmpd
    cmd="systemctl restart snmp"
    os.system (cmd)

@snmpagentaddress.command('del')
@click.argument('agentip', metavar='<SNMP AGENT LISTENING IP Address>', required=True)
@click.option('-p', '--port', help="SNMP AGENT LISTENING PORT")
@click.option('-v', '--vrf', help="VRF Name mgmt/DataVrfName/None")
@click.pass_context
def del_snmp_agent_address(ctx, agentip, port, vrf):
    """Delete the SNMP agent listening IP:Port%Vrf configuration"""

    key = agentip+'|'
    if port:
        key = key+port
    key = key+'|'
    if vrf:
        key = key+vrf
    config_db = ctx.obj['db']
    config_db.set_entry('SNMP_AGENT_ADDRESS_CONFIG', key, None)
    cmd="systemctl restart snmp"
    os.system (cmd)

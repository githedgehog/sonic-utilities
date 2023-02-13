import click
import utilities_common.cli as clicommon
from swsscommon.swsscommon import SonicV2Connector

@click.command()
@clicommon.pass_db
def radius(db):
    """Show RADIUS configuration"""
    output = ''
    config_db = db.cfgdb
    data = config_db.get_table('RADIUS')

    radius = {
        'global': {
            'auth_type': 'pap (default)',
            'retransmit': '3 (default)',
            'timeout': '5 (default)',
            'passkey': '<EMPTY_STRING> (default)'
        }
    }
    if 'global' in data:
        radius['global'].update(data['global'])
    for key in radius['global']:
        output += ('RADIUS global %s %s\n' % (str(key), str(radius['global'][key])))

    data = config_db.get_table('RADIUS_SERVER')
    if data != {}:
        for row in data:
            entry = data[row]
            output += ('\nRADIUS_SERVER address %s\n' % row)
            for key in entry:
                output += ('               %s %s\n' % (key, str(entry[key])))

    counters_db = SonicV2Connector(host='127.0.0.1')
    counters_db.connect(counters_db.COUNTERS_DB, retry_on=False)

    if radius['global'].get('statistics', False) and (data != {}):
        for row in data:
            exists = counters_db.exists(counters_db.COUNTERS_DB,
                                     'RADIUS_SERVER_STATS:{}'.format(row))
            if not exists:
                continue

            counter_entry = counters_db.get_all(counters_db.COUNTERS_DB,
                    'RADIUS_SERVER_STATS:{}'.format(row))
            output += ('\nStatistics for RADIUS_SERVER address %s\n' % row)
            for key in counter_entry:
                if counter_entry[key] != "0":
                    output += ('               %s %s\n' % (key, str(counter_entry[key])))
    try:
        counters_db.close(counters_db.COUNTERS_DB)
    except Exception as e:
        pass

    click.echo(output)

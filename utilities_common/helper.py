import os

def get_exclude_cfg_list():
    """ Returns a list with the disabled config options
        the corresponding CLI should be excluded.
    """
    cur_file_path = os.path.dirname(os.path.abspath(__file__))
    exclude_cli_path = os.path.join(cur_file_path, '../', 'exclude-cfg', 'exclude-cfg.yaml')
    with open(exclude_cli_path) as exclude_cli_file:
        exclude_cli_list = [line.rstrip() for line in exclude_cli_file]

    return exclude_cli_list

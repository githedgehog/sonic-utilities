import click
import utilities_common.cli as clicommon
import yaml
import datetime


# There are no file existance cheks bcs this CLI group will not
# be loaded without metadata file (there is check in main.py)
METADATA_PATH = "/etc/sonic/build_metadata.yaml"


#
# 'metadata' group ("show metadata ...")
#

# 'metadata' subcommand ("show metadata")
@click.group(cls=clicommon.AliasedGroup, invoke_without_command=True)
@click.pass_context
def metadata(ctx):
    """Show build metadata related information"""
    if ctx.invoked_subcommand is None:
        with open(METADATA_PATH, 'r') as file:
            try:
                print(yaml.dump(yaml.safe_load(file), sort_keys=False))
            except:
                print("Error while processing {} file. Please check if file is correct!".format(METADATA_PATH))

# 'id' subcommand ("show metadata id")
@metadata.command()
def id():
    """Show build ID"""
    meta_key = 'id'
    yaml_key_helper(meta_key)


# 'date' subcommand ("show metadata date")
@metadata.command()
@click.option('-u', '--unix', is_flag=True, help="Show date in UNIX format")
def date(unix):
    """Show build timestamp"""
    meta_key = 'date'
    date = yaml_key_helper(meta_key, print_res=False, return_res=True)

    if unix is False:
        date = datetime.datetime.fromtimestamp(int(date))

    print(date)


# 'channel' subcommand ("show metadata channel")
@metadata.command()
def channel():
    """Show build channel branch"""
    meta_key = 'channel'
    yaml_key_helper(meta_key)


#
# 'git' group ("show metadata git ...")
#

# 'git' subcommand ("show metadata git")
@metadata.group(invoke_without_command=True)
@click.pass_context
def git(ctx):
    """Show build Git related info"""
    if ctx.invoked_subcommand is None:
        meta_key = 'git'
        yaml_key_helper(meta_key)


# 'repo' subcommand ("show metadata git repo")
@git.command()
def repo():
    """Show build Git repository link"""
    meta_key = ['git', 'repo']
    yaml_key_helper(meta_key)


# 'branch' subcommand ("show metadata git branch")
@git.command()
def branch():
    """Show build Git branch"""
    meta_key = ['git', 'branch']
    yaml_key_helper(meta_key)


# 'commit' subcommand ("show metadata git commit")
@git.command()
def commit():
    """Show build Git commit"""
    meta_key = ['git', 'ref']
    yaml_key_helper(meta_key)

#
# 'git' group ("show metadata git ...") end
#

#
# 'specification' group ("show metadata specification ...")
#

# 'specification' subcommand ("show metadata specification")
@metadata.group(invoke_without_command=True)
@click.pass_context
def specification(ctx):
    """Show build specification info"""
    if ctx.invoked_subcommand is None:
        meta_key = 'spec'
        yaml_key_helper(meta_key)


# 'platform' subcommand ("show metadata specification platform")
@specification.command()
def platform():
    """Show build platform"""
    meta_key = ['spec', 'platform']
    yaml_key_helper(meta_key)


# 'architecture' subcommand ("show metadata specification architecture")
@specification.command()
def architecture():
    """Show build architecture"""
    meta_key = ['spec', 'arch']
    yaml_key_helper(meta_key)


# 'usecase' subcommand ("show metadata specification usecase")
@specification.command()
def usecase():
    """Show image preset"""
    meta_key = ['spec', 'usecase']
    yaml_key_helper(meta_key)


# 'options' subcommand ("show metadata specification options")
@specification.command()
def options():
    """Show image options"""
    meta_key = ['spec', 'options']
    yaml_key_helper(meta_key)

#
# 'specification' group ("show metadata specification ...") end
#

#
# 'version' group ("show metadata version ...")
#

# 'version' subcommand ("show metadata version")
@metadata.group(invoke_without_command=True)
@click.pass_context
def version(ctx):
    """Show build version info"""
    if ctx.invoked_subcommand is None:
        meta_key = 'version'
        yaml_key_helper(meta_key)


# 'sonic' subcommand ("show metadata version sonic")
@version.command()
def sonic():
    """Show SONiC software version"""
    meta_key = ['version', 'SONiC_Software_Version']
    yaml_key_helper(meta_key)


# 'distribution' subcommand ("show metadata version distribution")
@version.command()
def distribution():
    """Show Debian version"""
    meta_key = ['version', 'distribution']
    yaml_key_helper(meta_key)


# 'kernel' subcommand ("show metadata version kernel")
@version.command()
def kernel():
    """Show Kernel version"""
    meta_key = ['version', 'kernel']
    yaml_key_helper(meta_key)


# 'date' subcommand ("show metadata version date")
@version.command()
def date():
    """Show build date"""
    meta_key = ['version', 'build_date']
    yaml_key_helper(meta_key)

#
# 'version' group ("show metadata version ...") end
#

# 'config' subcommand ("show metadata config")
@metadata.command()
@click.option('-o', '--option', default=[None], multiple=True, help="the index of PSU")
@click.option('-s', '--substring', is_flag=True, default=False, show_default=True, help="Find option as substring of key")
def config(option, substring):
    """Show build configuration options"""
    meta_key = 'configuration'

    if option[0] is None:
        yaml_key_helper(meta_key)
        return

    conf = yaml_key_helper(meta_key, print_res=False, return_res=True)
    result = {}
    if substring is False:
        for opt in option:
            if opt in conf:
                result[opt] = conf[opt]
    else:
        for opt in option:
            for key, _ in conf.items():
                if opt.lower() in key.lower():
                    result[key] = conf[key]
    
    for key, value in result.items():
        print(f"{key}: {value}")
    # Add new line to align with json.dump() 
    print("")


def strip_dots(s):
    """
    YAML.dump adds 3 dots at the end if there is
    one key in yaml. Strip them.
    """
    if isinstance(s, str) and s.endswith('...\n'):
       return s[:-4]
    return s


def yaml_key_helper(key=None, print_res=True, return_res=False):
    """
    """
    with open(METADATA_PATH, 'r') as file:
        try:
            metadata = yaml.safe_load(file)

            if isinstance(key, list):
                deep_key = metadata
                for k in key:
                    deep_key = deep_key[k]
                to_print = strip_dots(yaml.dump(deep_key, sort_keys=False))
                to_return = deep_key
            else:
                to_print = strip_dots(yaml.dump(metadata[key], sort_keys=False))
                to_return = metadata[key]

            if print_res:
                print(to_print)
            if return_res:
                return to_return
        except yaml.scanner.ScannerError:
            print("Error while loading {} file. Please check if file is correct!".format(METADATA_PATH))
        except KeyError:
            print("There is no key \"{}\" in metadata file.".format(key))

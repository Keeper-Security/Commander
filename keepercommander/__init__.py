import sys
import click

from keepercommander import cli, display, api

__version__ = '0.3.6'

@click.group()
@click.option('--server', '-s', envvar='KEEPER_SERVER', help='Host address')
@click.option('--user', '-u', envvar='KEEPER_USER', help='Email address for the account')
@click.option('--password', '-p', envvar='KEEPER_PASSWORD', help='Master password for the account')
@click.option('--config', help='Config file to use')
@click.option('--debug', 'debug', flag_value=True, help='Turn on debug mode')
@click.version_option(version=__version__)
@click.pass_context
def main(ctx, debug, server, user, password, config):

    try:
        params = cli.get_params(config)
        ctx.obj = params
    except Exception as e:
        print(e)
        sys.exit(1)

    if debug:
        params.debug = debug
    if server:
        params.server = server
    if user:
        params.user = user
    if password:
        params.password = password

main.add_command(cli.info)
main.add_command(cli.shell)
main.add_command(cli.list)
main.add_command(cli.export)
main.add_command(cli._import)
main.add_command(cli.delete_all)

if __name__ == "__main__":
    sys.exit(main())

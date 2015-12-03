import os

from click.testing import CliRunner
from keepercommander import main, __version__

TEST_CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'config.json')
print('\nConfig file: ' + TEST_CONFIG_FILE)

def test_version():
    runner = CliRunner()
    result = runner.invoke(main, ['--version'])
    assert __version__ in  result.output
    assert result.exception == None
    assert result.exit_code == 0

def test_list():
    runner = CliRunner()
    result = runner.invoke(main, ['--config', TEST_CONFIG_FILE, 'list'])
    assert result.exception == None
    assert result.exit_code == 0

def test_list_wrong_password():
    runner = CliRunner()
    result = runner.invoke(main, ['-p', 'fail', '--config', TEST_CONFIG_FILE, 'list'])
    assert result.exception != None
    assert result.exit_code != 0

def test_export_tab_separated():
    runner = CliRunner()
    result = runner.invoke(main, ['--config', TEST_CONFIG_FILE, 'export', 'keeper.txt'])
    assert result.exception == None
    assert result.exit_code == 0

def test_export_json():
    runner = CliRunner()
    result = runner.invoke(main, ['--config', TEST_CONFIG_FILE, 'export', '--format', 'json', 'keeper.json'])
    assert result.exception == None
    assert result.exit_code == 0

def test_import():
    runner = CliRunner()
    result = runner.invoke(main, ['--config', TEST_CONFIG_FILE, 'import', 'keeper.txt'])

    assert result.exception == None
    assert result.exit_code == 0

def test_delete_all():
    runner = CliRunner()
    result = runner.invoke(main, ['--config', TEST_CONFIG_FILE, 'delete-all'], input='y')
    assert result.exception == None
    assert result.exit_code == 0
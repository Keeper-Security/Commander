Keeper Commander for Python 3
----

This is the codebase for a Python 3 interface to Keeper.  This README is specific to running Keeper from the Python code.  Most users should install Commander as instructed in the main README page.

### Installation

This type of installation assumes you want to view/modify the source code. Using the instructions below,
you will be able to have more than one copy of keeper commander installed without conflicting with each other.

1) Install Python3 from [python.org](https://www.python.org)

2) Install virtualenv:

```bash
sudo pip3 install virtualenv
```

3) Create and activate the virtual environment for your keeper project:

```bash
cd /path/to/Commander
virtualenv -p python3 venv
source venv/bin/activate
```

4) Install the required modules

```bash
pip install -r requirements.txt
```

5) Install the keeper package in development mode

```bash
pip install -e .
```

NOTE: Keeper Commander is only compatible with Python 3.4+

Keeper supports plugins for various 3rd party systems for password reset integration.  Depending on the plugin, you will need to install the modules required.  For example, to support our MySQL plugin:

```bash
pip3 install PyMySQL
```

6) Set up a Keeper account from https://keepersecurity.com if you don't already have one.

7) Run Keeper by typing 

```bash
keeper 
```

It will print the help screen with available commands and options 

To run the interactive shell, type:
```bash
keeper shell
```

### Custom integrations

See the [custom](https://github.com/Keeper-Security/Commander/tree/master/keepercommander/custom) folder for examples on creating your own custom scripts to interface with Keeper from your own source code.

### Unit Tests

Commander uses ```unittest``` testing framework. To run unit tests, type
```
python3 -m unittest discover unit-tests
```
in ```Commander``` folder

### Help

If you need help, found a bug, or you're interested in contributing, email us at commander@keepersecurity.com.


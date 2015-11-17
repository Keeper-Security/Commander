Keeper Commander for Python 3
----

This is the codebase for a Python 3 interface to Keeper.

### Installation

This type of installation assumes you want to view/modify the source code. Using the instructions below,
you will be able to have more than one copy of keeper commander installed without conflicting with each other.

1) Install Python3 from [python.org](https://www.python.org)

2) Install virtualenv:

```
sudo pip3 install virtualenv
```

3) Create and activate the virtual environment for your keeper project (you need to be in the keeper root folder):

```
virtualenv -p python3 venv
source venv/bin/activate
```

4) Install the required modules

```
pip install -r requirements.txt
```

5) Install the keeper package in development mode

```
pip install -e .
```

NOTE: Keeper Commander is only compatible with Python 3.4+

Keeper supports plugins for various 3rd party systems for password reset integration.  Depending on the plugin, you will need to install the modules required.  For example, to support our MySQL plugin:

```
pip3 install PyMySQL
```

6) Set up a Keeper account from https://keepersecurity.com if you don't already have one.

7) Execute command line program as described below or use a config.json file to streamline usage.  Command line arguments will override the configuration file.

### Help

If you need help, found a bug, or you're interesting in contributing, email us at ops@keepersecurity.com.
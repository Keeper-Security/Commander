Keeper Commander for Python3
----

This is the codebase for a Python3 interface to Keeper.

### Installation 

1. Install Python3 from python.org.
2. Set up a Keeper account from https://keepersecurity.com
3. Create a config.json file.  Keeper Commander loads default 
configuration from the config.json file in the current folder.

Example file:

```
{ 
  "email":"craiglurey@gmail.com", 
  "password":"123456", 
  "mfa":"113355", 
  "debug":true, 
  "gui":false 
}
```

### Usage

```
python3 keeper.py 
```

You can login via the email/password/mfa stored in the config file,
or you will be prompted to enter your email, master pass and 
optional MFA token on the command prompt.

Once you are logged in, you can execute a variety of things.

### Helpful documentation

Basic Info:

    https://docs.python.org/3/index.html

Command line parsing:

    https://docs.python.org/3/howto/argparse.html#id1

pprint:

    https://docs.python.org/3/library/pprint.html

json:

    https://docs.python.org/3/library/json.html

### Using Keeper Commander




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

### Command-Line Usage

```
python3 keeper.py
```

You can login via the email/password/mfa stored in the config file,
or you will be prompted to enter your email, master pass and 
optional MFA token on the command prompt.

Once you are logged in, you can execute a variety of things.

TBD command reference will go here...


### Helpful documentation

Basic Info:

    [Python3 Tutorials](https://docs.python.org/3/index.html)

Command line parsing:

    [Command line parser](https://docs.python.org/3/howto/argparse.html)

pprint:

    [pprint](https://docs.python.org/3/library/pprint.html)

json:

    [JSON parser](https://docs.python.org/3/library/json.html)



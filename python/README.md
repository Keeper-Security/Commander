Keeper Commander for Python3
----

This is the codebase for a Python3 interface to Keeper.

### Installation 

1. Install Python3 from python.org.
2. Set up a Keeper account from https://keepersecurity.com
3. Create a config.json file.  Keeper Commander loads default 
configuration from the config.json file in the current folder.

### Dependencies

```
pip3 install requests
```

Example file:

```
{                                                                               
    "server":"https://dev2.keeperapp.com/v2/",                                  
    "email":"myusername@gmail.com",                                             
    "password":"123456",                                                       
    "mfa_token":"",                                                             
    "debug":true                                                                
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

VIM configuration used by Craig:

```
git clone https://github.com/sentientmachine/Pretty-Vim-Python.git
mv Pretty-Vim-Python/* ~/.vim/
```

Update ~/.vimrc:

```
set tabstop=4
set shiftwidth=4
set expandtab
set softtabstop=4
set smartindent
set autoindent
set hlsearch
set incsearch
set showmatch
set number

syntax on
colorscheme molokai
highlight Comment cterm=bold

:set textwidth=79                                                                  
:set colorcolumn=+1                                                                

```

Basic Info:

    [Python3 Tutorials](https://docs.python.org/3/index.html)

Command line parsing:

    [Command line parser](https://docs.python.org/3/howto/argparse.html)

pprint:

    [pprint](https://docs.python.org/3/library/pprint.html)

json:

    [JSON parser](https://docs.python.org/3/library/json.html)

requests:
    [Requests Module](http://requests.readthedocs.org/en/latest/)

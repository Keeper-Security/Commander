Keeper Commander for Python3
----

This is the codebase for a Python3 interface to Keeper.

### Installation 

1. Install Python3 from python.org and the below modules:

```
pip3 install requests
pip3 install pycrypto
```

2. Set up a Keeper account from https://keepersecurity.com if you don't 
already have one.

3. Execute command line program as described below or use 
a config.json file to streamline usage.  Command line arguments will 
override the configuration file.

### Command-line overrides

./keeper

./keeper --debug

./keeper --debug --email=email@company.com --command="get ASLK4nf42k3jd"

### Auto-configuration file

Place the file config.json in the install folder.  Example below:

```
{                                                                               
    "server":"https://dev2.keeperapp.com/v2/",
    "email":"myusername@gmail.com",
    "password":"123456",
    "mfa_token":"",
    "mfa_type":"",
    "debug":true
}
```

If you don't provide an email or password, you will be prompted
for this information when using Commander.

Once you are logged in, you can execute a variety of things.

### Commands


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

highlight OverLength ctermbg=red ctermfg=white guibg=#592929
match OverLength /\%81v.\+/
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

pycrypto:

    [PYCrypto Module](https://www.dlitz.net/software/pycrypto/api/current/)

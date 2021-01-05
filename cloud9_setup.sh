# Use this to set up the cloud9 environment
set -e

if [ ! -e "$HOME/environment" ]; then
  echo "This is not a cloud 9 environment!"
  exit 1;
fi

CODE_DIR="$HOME/environment";
GIT_CONFIG_PATH="$HOME/.gitconfig"
SSH_CONFIG_PATH="$HOME/.ssh/config"
SSH_GIT_PRV_KEY_PATH="$HOME/.ssh/id_rsa"
SSH_GIT_PRV_KEY_CHECK='BEGIN RSA PRIVATE KEY'
GIT_KCMD_PATH="$CODE_DIR/Commander"
KC_INIT="$HOME/.bash_kc"

GIT_KCMD_SSL='github:Keeper-Security/Commander.git'

if [ ! -e "${SSH_GIT_PRV_KEY_PATH}" ] ; then
  echo "Please upload your git SSH key, to this path: ${SSH_GIT_PRV_KEY_PATH}"
  echo 'And restart this script that file is present.'
else
  echo "Git SSH key appears to be present"
  chmod 600 ${SSH_GIT_PRV_KEY_PATH}
fi

if [ -z $(grep -o '\[user\]' ${GIT_CONFIG_PATH}) ] ; then
  echo 'Please Type you name as you want it to appear on git commits!'
  read git_name
  echo 'Please Type you email as you want it to appear on git commits!'
  read git_email
  cat > ${GIT_CONFIG_PATH} <<EOF
[credential]
        helper = !aws codecommit credential-helper $@
        UseHttpPath = true
[core]
        editor = /usr/bin/nano
[user]
  name = $git_name
  email = $git_email
EOF
  echo 'Git config is now configured'
else
  echo 'Git commit user name and email is setup'
fi

if [ ! -e "${SSH_CONFIG_PATH}" ]; then
  cat > ${SSH_CONFIG_PATH} <<EOF
LogLevel                ERROR
UserKnownHostsFile      /dev/null
StrictHostKeyChecking no
Host github
  HostName github.com
  User git
EOF
else
  echo 'SSH is already configured for git'
fi

if [ ! -e "${GIT_KCMD_PATH}" ]; then
  cd $CODE_DIR
  git clone ${GIT_KCMD_SSL}
  cd $GIT_KCMD_PATH
  virtualenv -p python3 venv
  source venv/bin/activate
  pip install -r requirements.txt
  pip install -e .
else
  echo "Keeper Commander has already been cloned!"
fi

if [ ! -e "${KC_INIT}" ]; then
  echo 'Setting up dev alias KC.'
  cat > ${KC_INIT} <<EOF
alias KC='cd $GIT_KCMD_PATH && source venv/bin/activate ; echo "Cmd to exit: deactivate!"'
EOF
else
  echo 'Dev alias KC already exists.'
fi

if [ -z $(grep -o "$KC_INIT" ~/.bashrc) ] ; then
  echo 'Initalizing dev alias KC.'
  echo "source $KC_INIT" >> ~/.bashrc
fi

echo '######################################################'
echo 'Logout and back in'
echo 'To start Keeper Command Python virtualenv, type "KC"'
echo 'To exit type "deactivate"'
echo '######################################################'

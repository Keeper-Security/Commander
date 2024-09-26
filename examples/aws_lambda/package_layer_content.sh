#!/usr/bin/env bash

#   To create a `keepercommander` dependency layer for your AWS Lambda function :
#   1. Upload this script to any folder in your CloudShell environment.
#   2. (Optional) Upload your project's `requirements.txt` file  to the same folder.
#   3. In that folder, run
#             source ./package_layer_content.sh
#   4. There should now be a file named `commander-layer.zip` that can be uploaded
#     to your S3 bucket, where it can then be used to create a new Lambda layer

MAX_LIB_SIZE=262144000
LAYER_FILENAME='commander-layer.zip'
LAYER_PATH=$(pwd)/$LAYER_FILENAME
LIB_DIR='python'
VENV='commander-venv'
OTHER_DEPS='requirements.txt'

# Clean up previous artifacts
test -f $LAYER_FILENAME && rm $LAYER_FILENAME
test -d $LIB_DIR && rm -rf $LIB_DIR
test -d $VENV && rm -rf $VENV

# Create package folder to zip
mkdir $LIB_DIR

# Create and run virtual environment
python -m venv $VENV
source ./$VENV/bin/activate

# Install dependencies and package
pip install cryptography --platform manylinux2014_x86_64 --only-binary=:all: -t $LIB_DIR
pip install keepercommander -t $LIB_DIR

if test -f $OTHER_DEPS; then
  pip install -r $OTHER_DEPS -t $LIB_DIR
fi

deactivate

# Check uncompressed library size
LIB_SIZE=$(du -sb $LIB_DIR | cut -f 1)
LIB_SIZE_MB=$(du -sm $LIB_DIR | cut -f 1)

if [ "$LIB_SIZE" -ge $MAX_LIB_SIZE ]; then
  echo "*****************************************************************************************************************"
  echo 'Operation was aborted'
  echo "The resulting layer has too many dependencies and its size ($LIB_SIZE_MB MB) exceeds the maximum allowed (~262 MB)."
  echo 'Try breaking up your dependencies into smaller groups and package them as separate layers.'
  echo "*****************************************************************************************************************"
else
  zip -r $LAYER_FILENAME $LIB_DIR
  echo "***************************************************************************"
  echo "***************************************************************************"
  echo 'Lambda layer file has been created'
  printf "To download, copy the following file path: %s\n%s\n$LAYER_PATH%s\n%s\n"
  echo 'and click on "Actions" in the upper-right corner of your CloudShell console'
  echo "***************************************************************************"
fi

# Clean-up
rm -rf $LIB_DIR
rm -rf $VENV

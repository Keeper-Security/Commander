#!/bin/bash
env=$1
if [ "$env" = "dev" ]
then
    echo "dev"
    python -m keepercommander shell --server dev.keepersecurity.com
else
    echo "prod"
    python -m keepercommander shell --server keepersecurity.com
fi

#!/bin/bash
 
set -e  # exit on error

if [[ -n ${GITHUB_TOKEN} ]]; then
  git config --global url."https://${GITHUB_TOKEN}:x-oauth-basic@github.com/akeylesslabs".insteadOf "https://github.com/akeylesslabs"
fi

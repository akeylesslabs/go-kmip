#!/usr/bin/env bash

set -e

function usage() {
	cat <<EOF
Usage: $0
    [--target] [--cache]

optional arguments:
    --target         test target (options: "all", "kmip")
    --cache          skip the tests cache cleanup
    --go-tags        Go tags
    --no-verbose     Run tests with no verbosity
EOF
	exit 1
}

function handle_parameters() {
    target="all"
    cleanCache=true
    go_tags=''
    verbose="-v"

    until [[ -z $1 ]]; do
        case $1 in
        --go-tags )
            go_tags="$2"
            shift
            ;;
        --target )
            target="$2"
            shift
            ;;
        --cache )
            cleanCache=false
            ;;
         --no-verbose )
            verbose=""
            ;;
        * )
            usage
            ;;
        esac
        shift
    done
}

all_tests_list=\
( \
    "kmip" \
)

function test_kmip() {
  echo "Testing KMIP package"
  cd ./work/go-kmip/go-kmip
  go test -v -failfast -race -timeout 300s ./... ${go_tags:+"-tags" "$go_tags"}
}

# ========== Start main script ============
handle_parameters $*
# Running inside github context
if [[ -n "${GITHUB_CONTEXT}" ]]; then
# For self-hosted runners
  sudo service rsyslog start
fi

currentDir=$(pwd)
cd ${code_root}

if [[ ${cleanCache} = true ]] ; then
    go clean -testcache
fi

if [[ $target == "all" ]]; then
  for test_func in ${all_tests_list[@]}; do
    cmd="test_${test_func}"
    set -euo pipefail
    eval $cmd
  done
elif [[ "$target" =~ (kmip) ]]; then


  cmd="test_${target//-/_}"
  set -euo pipefail
  eval $cmd
else
    echo "error: invalid target"
    cd ${currentDir}
    usage
fi

cd ${currentDir}

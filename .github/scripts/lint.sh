#!/bin/bash

gofmt_output=$(gofmt -s -l -d .)
if [ -n "$gofmt_output" ]; then
  echo "The following files need formatting:"
  echo "$gofmt_output"
  exit 1
else
  echo "All files are properly formatted."
fi

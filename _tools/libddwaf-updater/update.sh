#!/bin/bash

cd "$(dirname "$0")" || exit
exec go run ./update.go "$@"

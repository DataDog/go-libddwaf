#!/bin/bash

cd $(dirname $0)
exec go run ./update.go

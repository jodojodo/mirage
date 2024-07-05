#!/bin/sh

SCRIPT=$(readlink -f "$0")
BASEDIR=$(dirname "$SCRIPT")

sudo -E env PATH=$PATH "$BASEDIR/mirage_launcher" $@

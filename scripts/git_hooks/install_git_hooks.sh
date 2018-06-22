#!/bin/sh

CURDIR=$(dirname "$(readlink -m "$0")")
TOPDIR=$(git rev-parse --show-toplevel)
HOOKDIR=$TOPDIR/.git/hooks

cp -f "$CURDIR/pre-commit" "$HOOKDIR"
chmod +x  "$HOOKDIR/pre-commit"

cp -f "$CURDIR/commit-msg" "$HOOKDIR"
chmod +x "$HOOKDIR/commit-msg"


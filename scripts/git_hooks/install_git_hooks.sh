#!/bin/sh

set -eu

CURDIR=$(dirname "$(readlink -m "$0")")
GITDIR=$(git rev-parse --git-dir)
HOOKDIR=$GITDIR/hooks

if [[ ! -e "$HOOKDIR" ]]; then
	echo "$HOOKDIR does not exist, install hook on main worktree?"
	exit 1
fi

cp -vf "$CURDIR/pre-commit" "$HOOKDIR"
chmod +x  "$HOOKDIR/pre-commit"

cp -vf "$CURDIR/commit-msg" "$HOOKDIR"
chmod +x "$HOOKDIR/commit-msg"


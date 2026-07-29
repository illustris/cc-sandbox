#!/bin/sh
set -eu

name=${0##*/}

fail() {
	printf '%s: %s\n' "$name" "$*" >&2
	exit 1
}

[ "$#" -eq 2 ] || fail "usage: $name PERSISTENT_HOME LINK_PATH"

persistent_home=$1
link_path=$2

[ "$persistent_home" != "$link_path" ] || fail "persistent home and link path must differ"

# Validate both paths before changing either one. In particular, a conflicting
# image home must not cause even an empty persistent home to be created.
target_missing=false
if [ -L "$persistent_home" ]; then
	fail "persistent home $persistent_home is a symlink, not a real directory"
elif [ -e "$persistent_home" ]; then
	[ -d "$persistent_home" ] || fail "persistent home $persistent_home is not a directory"
else
	target_missing=true
fi

link_state=absent
if [ -L "$link_path" ]; then
	link_target=$(readlink "$link_path") || fail "cannot read symlink $link_path"
	[ "$link_target" = "$persistent_home" ] || fail "home link $link_path points to $link_target, expected $persistent_home"
	link_state=correct
elif [ -e "$link_path" ]; then
	[ -d "$link_path" ] || fail "home link path $link_path is not a directory"
	first_entry=$(find "$link_path" -mindepth 1 -maxdepth 1 -print -quit) || fail "cannot inspect home directory $link_path"
	[ -z "$first_entry" ] || fail "home directory $link_path is nonempty; refusing to merge or remove it"
	link_state=empty-directory
fi

if [ "$target_missing" = true ]; then
	mkdir -m 700 -- "$persistent_home" || fail "cannot create persistent home $persistent_home"
fi
chmod 700 -- "$persistent_home" || fail "cannot set mode 0700 on persistent home $persistent_home"

case "$link_state" in
absent)
	ln -sT -- "$persistent_home" "$link_path" || fail "cannot create home link $link_path"
	;;
empty-directory)
	rmdir -- "$link_path" || fail "home directory $link_path is no longer empty; refusing to remove it"
	ln -sT -- "$persistent_home" "$link_path" || fail "cannot create home link $link_path"
	;;
correct) ;;
esac

#!/bin/sh

# Description:
#   Create mckernel-<version>.tar.gz
#
# Usage:
#   cd /tmp
#   <Documentation>/distribution/bin/make_distribution.sh

os_dir=${HOME}/project/os
tag=

while getopts v: OPT
do
        case ${OPT} in
	    v) tag=$OPTARG
		;;
            \?) exit 1
		;;
        esac
done

wc=`find . | wc -l`
if [ $wc -ne 1 ] ; then
    echo "Run this script on an empty directory."
    exit 1
fi

if [ -z "$tag" ]; then
    tag_ihk=`git ls-remote --tags git@github.com:RIKEN-SysSoft/ihk.git | tail -1 | cut -f 2 | perl -ne 'if (/.*\/([0-9.]*)/) { print $1; }'`
    tag_mck=`git ls-remote --tags git@github.com:RIKEN-SysSoft/ihk.git | tail -1 | cut -f 2 | perl -ne 'if (/.*\/([0-9.]*)/) { print $1; }'`
    tag_doc=`git ls-remote --tags postpeta@postpeta.pccluster.org:Documentation | tail -1 | cut -f 2 | perl -ne 'if (/.*\/([0-9.]*)/) { print $1; }'`

    if [ "$tag_ihk" != "$tag_mck" ]; then
	echo "Error: The last tag of ihk, ${tag_ihk}, and that of mckernel, ${tag_mck}, don't match"
	exit 1;
    fi

    if [ "$tag_ihk" != "$tag_doc" ]; then
	echo "Error: The last tag of ihk, ${tag_ihk}, and that of Documentation, ${tag_doc}, don't match"
	exit 1;
    fi

    tag=$tag_ihk
fi

read -p "Create a tarball of version ${tag}? [Y/n] " key
if [ "$key" == "n" ]; then
    exit 1;
fi

# Prevent Mac from inserting database files
export COPYFILE_DISABLE=1

mkdir mckernel-$tag &&
cd mckernel-$tag &&

# Prepare src/*

mkdir src &&
cd src &&

svn export -q https://github.com/RIKEN-SysSoft/ihk/tags/$tag &&
mv $tag ihk &&
rm -rf ihk/{.gitignore,doxygen} &&
if !grep $tag ihk/configure.ac 2>/dev/null >/dev/null; then
    echo "The version number in ihk/configure.ac isn't the same as the git tag";
    exit 1
fi

svn export -q https://github.com/RIKEN-SysSoft/mckernel/tags/$tag &&
mv $tag mckernel &&
rm -rf mckernel/{.gitignore,.gitmodules,doxygen,test} &&
if ! grep $tag mckernel/configure.ac 2>/dev/null >/dev/null; then
    echo "The version number in mckernel/configure.ac isn't the same as the git tag";
    exit 1
fi

cd .. &&

# Prepare doc/*

(git archive --prefix=doc/ --format=tar --remote=postpeta@postpeta.pccluster.org:Documentation $tag | tar -xf -) &&
mv doc/distribution/{LICENSE,README,RELEASE} ./ &&
mv doc/distribution/{CONTRIBUTORS,HOW_TO_USE} doc/ &&
mv doc/tutorial doc/_tutorial
mv doc/distribution/tutorial doc/ &&
mv doc/distribution/bin/config_and_build_smp_x86.sh ./ &&
rm -rf doc/distribution/{bin,syscalls_implemented.txt,tutorial}
rm -rf doc/{.gitignore,devel_notes,distribution,obsolete,spec,_tutorial,work} &&


# Pack them

cd .. &&
tar czf mckernel-$tag.tar.gz mckernel-$tag &&
rm -rf mckernel-$tag

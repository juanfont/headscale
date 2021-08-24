#!/usr/bin/env bash

set -e -o pipefail
commit="$1"
versionglob="v[0-9].[0-9]*.[0-9]*"
devsuffix=".dev"
if [ -z "$commit" ]; then
  commit=`git log -n1 --first-parent "--format=format:%h"`
fi

# automatically assign version
#
# handles the following cases:
#
# 0. no tags on the repository. Print "dev".
#
# 1. no local modifications and commit is directly tagged. Print tag.
#
# 2. no local modifications and commit is not tagged. Take greatest version tag in repo X.Y.Z and assign X.Y.(Z+1). Print that + $devsuffix + $timestamp.
#
# 3. local modifications. Print "dev".

tags=$(git tag)
if [[ -z "$tags" ]]; then
  echo "dev"
elif `git diff --quiet 2>/dev/null`; then
  tagged=$(git tag --points-at "$commit")
  if [[ -n "$tagged" ]] ; then
    echo $tagged
  else
    nearest_tag=$(git describe --tags --abbrev=0 --match "$versionglob" "$commit")
    v=$(echo $nearest_tag | perl -pe 's/(\d+)$/$1+1/e')
    isodate=$(TZ=UTC git log -n1 --format=%cd --date=iso "$commit")
    ts=$(TZ=UTC date --date="$isodate" "+%Y%m%d%H%M%S")
    echo "${v}${devsuffix}${ts}"
  fi
else
  echo "dev"
fi

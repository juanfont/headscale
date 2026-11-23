#!/bin/sh
set -eu

: "${RAPID_CHECKS:=64}"
export RAPID_CHECKS
fixtures='Parse|DispatchShortLines|CommandErrorIdentity|SealedListSeparator|InvalidFilterNoFiles|UserListJSONArray|AbsentNumericUser|IntegerColumnPrecision|IntegerFilterNearOne|IntegerFilterTinyNonzero|UsernameStartsWithHebrewLetter|UsernameMinimumRunes|UsernameDecimalDigit|UserFieldErrorCount'
exec go test -count=1 -buildvcs=false -p=2 -run "^Test(Rapid.*|$fixtures)$" "$@" \
    ./cmdline ./cmdline/reader ./cmd/headscale/newcli ./cmd/headscale/newcli/command \
    ./cmd/headscale/newcli/table ./hscontrol/api/headscale/v0 ./hscontrol/util

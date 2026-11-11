# ReplacesFile fixtures

`*-owner.apk` and `*-incoming.apk` are pairs of packages written by this
library that both ship the file `shared`; `generate.sh` installs the owner, then
the incoming package, in an empty root with the apk of an Alpine 3.24 container
and records in `expected` who got the file (`yes`: the incoming package, `no`:
the owner, `conflict`: apk refused). `TestReplacesFile` compares `ReplacesFile`
with it.

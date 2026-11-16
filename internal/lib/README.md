## Embedded WAF libraries

This directory contains Datadog's WAF static libraries taken from the releases
of https://github.com/DataDog/libddwaf

### Updating

From the root of the repository, run:

```console
./_tools/libddwaf-updater/update.sh
Will upgrade from v2.2.0 to v2.2.1
... downloaded <repo-root>/internal/lib/libddwaf-darwin-arm64.dylib.gz
... downloaded <repo-root>/internal/lib/libddwaf-darwin-amd64.dylib.gz
... downloaded <repo-root>/internal/log/ddwaf.h
... downloaded <repo-root>/internal/lib/libddwaf-linux-arm64.so.gz
... downloaded <repo-root>/internal/lib/libddwaf-linux-amd64.so.gz
All done! Don't forget to check in changes to internal/lib/ and internal/log/ddwaf.h, check the libddwaf upgrade guide to update bindings!
```

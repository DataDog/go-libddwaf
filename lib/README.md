## Embedded WAF libraries

This directory contains Datadog's WAF static libraries taken from the releases
of https://github.com/DataDog/libddwaf

### Updating

In order to update the embedded libraries, ensure you have a recent `node`
available on your system, then run:

```console
# Paths assume this runs from the repository root.
$ ./lib/bump.mjs
Latest libddwaf release: v1.15.0
Looking up asset for darwin-amd64...
... downloading from https://api.github.com/repos/DataDog/libddwaf/releases/assets/133245135
Looking up asset for darwin-arm64...
... downloading from https://api.github.com/repos/DataDog/libddwaf/releases/assets/133245141
Looking up asset for linux-amd64...
... downloading from https://api.github.com/repos/DataDog/libddwaf/releases/assets/133245129
Looking up asset for linux-arm64...
... downloading from https://api.github.com/repos/DataDog/libddwaf/releases/assets/133245130
Successfully updated embedded libraries from v1.13.0 to v1.15.0!
```

# hem-libjwt

Source Code Form of the files of the JWT C Library (libjwt) that are built into the
Encedo HEM firmware. They are covered by the Mozilla Public License 2.0, and this
repository makes them available as required by MPL-2.0 section 3.2(a).

## Origin

- Upstream: [benmcollins/libjwt](https://github.com/benmcollins/libjwt), version 1.11.0, by Ben Collins
- License: Mozilla Public License 2.0 (see [LICENSE](LICENSE)); every file keeps its MPL-2.0 notice

## Files

| File | Status |
|---|---|
| `include/jwt.h` | modified |
| `libjwt/jwt.c` | modified |
| `libjwt/jwt-private.h` | modified |
| `libjwt/jwt-wolfssl.c` | wolfSSL (wolfCrypt) backend, not part of upstream 1.11.0 |

Modifications: Copyright (c) 2019-2026 Krzysztof Rutecki, under the Mozilla Public License 2.0.

These are the only libjwt files compiled into the firmware. The rest of the firmware is a
separate work (a "Larger Work", MPL-2.0 section 3.3) and is not covered by this license.

## Firmware versions

The content matches Encedo HEM firmware 1.3.x.

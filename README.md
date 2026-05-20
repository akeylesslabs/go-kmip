go-kmip
=======

[![Build Status](https://travis-ci.org/smira/go-kmip.svg?branch=master)](https://travis-ci.org/smira/go-kmip)
[![codecov](https://codecov.io/gh/smira/go-kmip/branch/master/graph/badge.svg)](https://codecov.io/gh/smira/go-kmip)
[![Documentation](https://godoc.org/github.com/smira/go-kmip?status.svg)](http://godoc.org/github.com/smira/go-kmip)
[![Go Report Card](https://goreportcard.com/badge/github.com/smira/go-kmip)](https://goreportcard.com/report/github.com/smira/go-kmip)

go-kmip implements a subset of the [KMIP 1.4](http://docs.oasis-open.org/kmip/spec/v1.4/os/kmip-spec-v1.4-os.html) and [KMIP 2.0](https://docs.oasis-open.org/kmip/spec/v2.0/os/kmip-spec-v2.0-os.html) protocols.

Basic TTLV encoding/decoding is fully implemented, as well as the basic client/server operations. 
Other operations and fields could be implemented by adding required Go structures with KMIP tags.

KMIP protocol is used to access KMS solutions: generating keys, certificates,
accessing stored objects, etc.

KMIP is using TTLV-like encoding, which is implemented in this packaged
as encoding/decoding of Go struct types. Go struct fields are annotated with
`kmip` tags which specify KMIP tag names. Field is encoded/decoded according
to its tag, type.

Two high-level objects are implemented: Server and Client. Server listens for
TLS connections, does initial handshake and processes batch requests from the
clients. Processing of specific operations is delegated to operation handlers.
Client objects establishes connection with the KMIP server and allows sending
any number of requests over the connection.

This package doesn't implement any actual key processing or management - it's outside
the scope of this package.

KMIP 2.0 support
----------------

This branch adds initial KMIP 2.0 payload support alongside the existing 1.x implementation.

- A new subpackage `kmip20` registers KMIP 2.0 request/response payloads at init-time.
- Import it for side effects to enable 2.0 encoding/decoding:

```go
import (
    "github.com/akeylesslabs/go-kmip"
    _ "github.com/akeylesslabs/go-kmip/kmip20" // register KMIP 2.0 payloads
)
```

- Currently covered KMIP 2.0 operations:
  - Create
  - CreateKeyPair
  - Get
  - Register
  - Locate
  - SetAttribute
  - AdjustAttribute
  - ReKey
  - AddAttribute
  - ModifyAttribute
  - DeleteAttribute

- Notable 2.0 payload differences:
  - Uses the `ATTRIBUTES` structure (container of `ATTRIBUTE` items) instead of 1.x `TEMPLATE_ATTRIBUTE`.
  - `CreateKeyPair` accepts `COMMON_ATTRIBUTES`, `PRIVATE_KEY_ATTRIBUTES`, `PUBLIC_KEY_ATTRIBUTES`.

- Backward compatibility:
  - 1.x payloads remain the default; registering 2.0 payloads does not replace 1.4 payloads.
  - Decoding/encoding chooses payloads based on the `ProtocolVersion` in the KMIP header.
  - For some operations (e.g., Get, ReKey, Add/Modify/Delete Attribute), KMIP 2.0 reuses the 1.x payload structures; `kmip20` registers factories to select those under 2.0.

Minimal example (KMIP 2.0 Create)
---------------------------------

```go
package main

import (
    "bytes"
    "github.com/akeylesslabs/go-kmip"
    "github.com/akeylesslabs/go-kmip/kmip20"
)

func main() {
    req := kmip.Request{
        Header: kmip.RequestHeader{ // build header with KMIP 2.0
            Version:    kmip.ProtocolVersion{Major: 2, Minor: 0},
            BatchCount: 1,
        },
        BatchItems: []kmip.RequestBatchItem{
            {
                Operation: kmip.OPERATION_CREATE,
                RequestPayload: kmip20.CreateRequest{
                    ObjectType: kmip.OBJECT_TYPE_SYMMETRIC_KEY,
                    Attributes: kmip20.Attributes{},
                },
            },
        },
    }
    var buf bytes.Buffer
    _ = kmip.NewEncoder(&buf).Encode(req)
}
```

License
-------

This code is licensed under [MPL 2.0](https://www.mozilla.org/en-US/MPL/2.0/).

# gcid

Idiomatic Go implementation of the GCIDv2 wire format.

```go
package main

import (
	"fmt"
	"log"

	"github.com/jrepp/gcid/go/gcid"
)

func main() {
	codec, err := gcid.NewCodec([]byte("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"))
	if err != nil {
		log.Fatal(err)
	}

	id, err := codec.Encode("prf", 123)
	if err != nil {
		log.Fatal(err)
	}

	decoded, err := codec.DecodeID("prf", id)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(id.String(), decoded.Sequence)
}
```

Run tests and benchmarks from this directory:

```sh
go test ./...
go test -bench=. -benchmem ./...
```

Recent local result on Apple Silicon:

```text
BenchmarkEncode-6           10301 ns/op    376 B/op    11 allocs/op
BenchmarkDecode-6           13015 ns/op    195 B/op     9 allocs/op
BenchmarkKeyringDecode-6    13613 ns/op    192 B/op     9 allocs/op
```

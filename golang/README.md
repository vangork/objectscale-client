# ObjectScale Golang client

To use the golang client, make sure to checkout this repo and build locally as the golang client uses cgo and calls objectscale c lib which is not shipped separately.

```
cd c && cargo build --release
```

Tu run integration test for golang client.

```
go test ./tests/ -v
```

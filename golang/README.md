# ObjectScale Golang client

[ObjectScale](https://www.dell.com/en-sg/shop/storage-servers-and-networking-for-business/sf/objectscale) Golang client, binden from Rust interface.


To use the golang client, make sure to checkout this repo and build locally as the golang client uses cgo and calls objectscale c lib which is not shipped separately.

```
cd c && cargo build --release
```

To run integration test for golang client.

```
go test ./tests/ -v
```

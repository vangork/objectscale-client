# ObjectScale Golang client

[ObjectScale](https://www.dell.com/en-sg/shop/storage-servers-and-networking-for-business/sf/objectscale) Golang client, binden from Rust interface.

## Development & Test
To use the golang client, make sure to build the C lib first as the Golang client wraps the C lib internally with cgo .

```
cd c && cargo build --release
```

To run integration test for golang client.

```
go test ./tests/ -v
```

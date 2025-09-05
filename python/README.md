# ObjectScale Python client

This project provides a way to interact with [ObjectScale](https://www.dell.com/en-hk/dt/storage/objectscale.htm) using Python client.

## Build & Install
Build the wheels package
```shell
pip install maturin
maturin build -b pyo3 -r
```

The client library can be installed via `pip` or `maturin`.
```shell
# via pip
pip install .

# via maturin
maturin develop
```

## Example
```
python ./examples/list_namespaces.py
```

## Distribute

To generate wheels using a docker approach
```
docker run --rm -v $(pwd)/..:/io -w /io/python ghcr.io/pyo3/maturin build -b pyo3 --release --strip
```

To publish the artifacts.
```
pip install twine
twine upload ../target/wheels/*
```

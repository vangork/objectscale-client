# ObjectScale Python client

This project provides a way to interact with [ObjectScale](https://www.dell.com/en-hk/dt/storage/objectscale.htm) using Python client.

## Install

The client library can be installed using pip.
```shell
pip install objectscale-client
```
Users can also choose to builds the crate and installs it as a python module directly using the commands specified at [README.md](https://github.com/vangork/objectscale-client?tab=readme-ov-file#python) .

## Example
```
python ./examples/list_accounts.py
```

## Distribute

To generate wheels using a docker approach
```
docker run --rm -v $(pwd)/..:/io -w /io/python -e http_proxy=http://172.17.0.1:1090 -e https_proxy=http://172.17.0.1:1090  ghcr.io/pyo3/maturin build --release --strip -i python3.9
```

To publish the artifacts.
```
pip install twine
twine upload ../target/wheels/*
```

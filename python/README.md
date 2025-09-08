# SealPIR Python bindings

This directory contains the packaging configuration for the `pysealpir` Python
extension. Building requires a C++17 compiler, pybind11, scikit-build-core and
Microsoft SEAL headers.

Python 3.11 requires pybind11 version 2.10 or newer.

To build and install locally run:

```bash
pip install -e .
```

This will compile the extension via CMake and make the module available as
`pysealpir`.

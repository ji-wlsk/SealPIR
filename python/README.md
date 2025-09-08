# SealPIR Python bindings

This directory contains the packaging configuration for the `sealpir` Python
extension. Building requires a C++17 compiler, pybind11, scikit-build-core and
Microsoft SEAL headers.

To build and install locally run:

```bash
pip install -e .
```

This will compile the extension via CMake and make the module available as
`sealpir`.

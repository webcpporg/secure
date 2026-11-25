# secure

secure holds the side-channel and secret-in-memory primitives that the libraries of
[webcpp](https://github.com/webcpporg/webcpp) share, for C++20 on every target webcpp has: native
(Linux, macOS, Windows with MSVC), wasip2, wasip3 and Emscripten. It holds no cryptographic
algorithm: the DIT timing guard, `erase_secret`, `secret<N>`, `constant_time_equal`, the
`declassify` marker and the constant-time building blocks, every name in `webcpp::secure`.

Every function is `noexcept` and none allocates; the library is header-only. Its page, `doc/secure.adoc`,
teaches each primitive with a program of `example/` and states what each covers and what it does
not; its design is the genesis of `libraries/secure` in
[webcpporg/proposals](https://github.com/webcpporg/proposals).

## Build and test

secure is built inside the [webcpp](https://github.com/webcpporg/webcpp) superproject, where it is
the submodule `libs/secure`; a program names `/webcpp/secure//secure`:

```jam
exe app : app.cpp /webcpp/secure//secure ;
```

From the superproject's root:

```
./b2 toolset=clang libs/secure/test libs/secure/example
```

## Documentation

The library's page is built with `./b2 libs/secure/doc doc` and published with webcpp's
documentation, at <https://webcpp.org>.

## Licence

Distributed under the Boost Software License, Version 1.0 (`LICENSE_1_0.txt`).

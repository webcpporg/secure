# secure

secure holds the side-channel and secret-in-memory primitives that the libraries of
[webcpp](https://github.com/webcpporg/webcpp) share, for C++20 on every target webcpp has: native
(Linux, macOS, Windows with MSVC), wasip2, wasip3 and Emscripten. It holds no cryptographic
algorithm: the DIT timing guard, `erase_secret`, `secret<N>`, `constant_time_equal`, the
`declassify` marker and the constant-time building blocks, every name in `webcpp::secure`.

The library is being built; its design is the genesis of `libraries/secure` in
[webcpporg/proposals](https://github.com/webcpporg/proposals).

## Licence

Distributed under the Boost Software License, Version 1.0 (`LICENSE_1_0.txt`).

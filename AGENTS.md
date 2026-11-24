# Working on secure

webcpp's rules apply here: read the superproject's
[CODING-GUIDELINES.md](../../CODING-GUIDELINES.md)
(<https://github.com/webcpporg/webcpp/blob/main/CODING-GUIDELINES.md>) and its
[AGENTS.md](../../AGENTS.md)
(<https://github.com/webcpporg/webcpp/blob/main/AGENTS.md>) first. This file holds only what is
specific to secure.

## What secure is

- **webcpp's own library** (`"port-of": null`), with **no algorithm**: the side-channel and
  secret-in-memory primitives that crypto, hash and the codecs share (the DIT timing guard,
  `erase_secret`, `secret<N>`, `constant_time_equal`, `declassify` and the constant-time building
  blocks).
- **Header-only**, every function `noexcept`; it raises no exception.

## Cautions

- A test is declared through `secure-run` (or `secure-compile`) in `test/Jamfile`, which builds it
  with exceptions and without.
- A test that defines a seam includes the seam's header first, before any header of secure.
- `detail` is not API: another library's header never includes it. Test code may call
  `secure::detail::write_dit`.

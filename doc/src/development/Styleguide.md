# Styleguide

## Code format

We rely on [rustfmt](https://github.com/rust-lang/rustfmt) to automatically format our code.

## Code imports

We organize/separate imports into three blocks (all separated by one newline):

- 1st block for core language things: `core`, `alloc`, `std` etc.
- 2nd block for libraries: `vibrio`, `x86`, `lazy_static` etc.
- 3rd block for internal imports: `crate::*`, `super::*` etc.

## Assembly

We use AT&T syntax for assembly code (`options(att_syntax)` in Rust `asm!`
blocks)

## Cargo features

Libraries and binaries only have non-additive / non-conflicting feature flags.
This helps to spot compilation problems quickly (e.g. with `cargo build
--all-features`)

## Formatting Commit Messages

We follow the conventions on [How to Write a Git Commit
Message](http://chris.beams.io/posts/git-commit/).

Be sure to include any related GitHub issue references in the commit message.
See [GFM
syntax](https://guides.github.com/features/mastering-markdown/#GitHub-flavored-markdown)
for referencing issues and commits.

# Styleguide

## Code format

We rely on [rustfmt](https://github.com/rust-lang/rustfmt) to automatically format our code.

## Code organization

We organize/separate imports into three blocks (all separated by one newline):

- 1st block for core language things: `core`, `alloc`, `std` etc.
- 2nd block for libraries: `vibrio`, `x86`, `lazy_static` etc.
- 3rd block for internal imports: `crate::*`, `super::*` etc.
- 4th block for re-exports: `pub(crate) use::*` etc.
- 5th block for modules: `mod foo;` etc.

Afterwards a `.rs` file should (roughly) have the following structure:

- 1st `type` declarations
- 2nd `const` declarations
- 3rd `static` declarations
- 4th `struct`, `fn`, `impl` etc. declarations

## Visibility

Avoid the use of `pub` in the kernel. Use `pub(crate)`, `pub(super)` etc. This
helps with dead code elimination.

## Assembly

We use AT&T syntax for assembly code (`options(att_syntax)` in Rust `asm!`
blocks)

## Cargo features

Libraries and binaries only have non-additive / non-conflicting feature flags.
This helps to spot compilation problems quickly (e.g. with `cargo build
--all-features`)

## Errors

The `KError` type is used to represent errors in the kernel. Whenever possible,
each variant should only be used once/in a single location (to be easy to grep
for) and should have a descriptive name.

## Formatting Commit Messages

We follow the conventions on [How to Write a Git Commit
Message](http://chris.beams.io/posts/git-commit/).

Be sure to include any related GitHub issue references in the commit message.
See [GFM
syntax](https://guides.github.com/features/mastering-markdown/#GitHub-flavored-markdown)
for referencing issues and commits.

## Github pull requests & history

Since github doesn't do fast-forward merges through the UI, after PR passes
test, merge it on the command line to keep the same commit hashes of the branch
in master:

```bash
git checkout master
git merge --ff-only feature-branch-name
```

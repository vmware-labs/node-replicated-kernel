# Configuration

## VSCode

VSCode generally works well for developing bespin. The Rust (rls) plugin doesn't
always work as expected due to `no-std` issues. Last time I checked,
`rust-analyzer` worked better but it sometimes takes a long time to run `cargo
check` which prevents you from building the project during that time.

## Git

To have better usability when working with submodules, you can set-up git to
update submodules automatically when doing `git pull` etc.

```bash
git config --global submodule.recurse true
```

Fetch multiple submodules in parallel:

```bash
git config --global submodule.fetchJobs 20
```

We don't allow merge requests on master, to always keep a linear history. The following
alias can be useful for helping with this:

```gitconfig
[alias]
    purr = pull --rebase
```

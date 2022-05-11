# Contributing to node-replicated-kernel

The node-replicted-kernel project team welcomes contributions from the community. If
you wish to contribute code and you have not signed our contributor license
agreement (CLA), our bot will update the issue when you open a Pull Request. For
any questions about the CLA process, please refer to our
[FAQ](https://cla.vmware.com/faq).

## Contribution Flow

This is a rough outline of what a contributor's workflow looks like:

- Create a topic branch from where you want to base your work
- Make commits of logical units
- Make sure your commit messages are in the proper format (see below)
- Push your changes to a topic branch in your fork of the repository
- Test changes locally
- Submit a pull request

Example:

Update latest master:

1. `git checkout master`
1. `git pull`
1. `git submodule update --init`

Create a new feature branch:

1. `git checkout -b <BRANCH-NAME>`
1. Make changes in code.

Make sure that the code compiles without warnings, is properly formatted and passes tests:

1. `cd kernel`
1. `bash commitable.sh`

Commit changes and push

1. `git add <CHANGED-FILES>`
1. `git commit`
1. `git push -u origin <BRANCH-NAME>`
1. Create a Pull Request on GitHub.

### Updating pull requests

If your PR fails to pass CI or needs changes based on code review, you'll most likely want to squash these changes into
existing commits.

If your pull request contains a single commit or your changes are related to the most recent commit, you can simply
amend the commit.

``` shell
git add .
git commit --amend
git push --force-with-lease origin my-new-feature
```

If you need to squash changes into an earlier commit, you can use:

``` shell
git add .
git commit --fixup <commit>
git rebase -i --autosquash master
git push --force-with-lease origin my-new-feature
```

Be sure to add a comment to the PR indicating your new changes are ready to review, as GitHub does not generate a
notification when you git push.

### Code Style

Be sure to follow the [style-guide](doc/src/development/Styleguide.md).

## Reporting Bugs and Creating Issues

When opening a new issue, try to roughly follow the commit message format conventions above.

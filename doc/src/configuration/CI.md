# CI

We run tests using the gitlab-runner infrastructure. The following steps are
necessary to set-up a new runner machine (and connect a github repo to it).

* Steps to configure a new repo for CI (needs to be done only once):

  1. Go to <https://gitlab.com/projects/new>
  1. Select tab 'CI/CD for external repo'
  1. Click github button
  1. Go to <https://github.com/settings/tokens> make a token with the `repo` and `admin:repo_hook` privilege
  1. Paste token in gitlab, select repo, click Connect
  1. In the gitlab.com project settings go to CI / CD to get the token ID for the setup
  1. On the same page, click on 'Disable shared Runners' to not use the gitlab.com pre-configured runner (won't work with our current CI scripts)
  1. In github.com Settings tab under Webhooks, change trigger to `push` events
    only (this avoid CI triggering twice -- when a pull request is created and
    when a push is made to the pull request)

* Steps to add a new CI machine:

  1. [Install gitlab-runner software on a new test machine](#install-gitlab-runner-software-on-a-new-test-machine)
  1. [Give access to the benchmark repository](#give-access-to-the-benchmark-repository)
  1. [Configure software for the `gitlab-runner` account](#configure-software-for-the-gitlab-runner-account)
  1. [Disable AppArmor](#disable-apparmor)
  1. [Do a test-run](#do-a-test-run)

## Install gitlab-runner software on a new test machine

Install the software package:

```bash
curl -LJO https://gitlab-runner-downloads.s3.amazonaws.com/latest/deb/gitlab-runner_amd64.deb
sudo dpkg -i gitlab-runner_amd64.deb
```

Add sudo capability for gitlab-runner:

```bash
visudo
# gitlab-runner  ALL=(ALL) NOPASSWD: ALL
```

Start the runner (should already run):

```bash
sudo gitlab-runner start
```

Next, create/register a runner
(<https://docs.gitlab.com/runner/register/index.html>) it should look like this:

```bash
$ sudo gitlab-runner register

Please enter the gitlab-ci coordinator URL (e.g. https://gitlab.com/):
<< gitlab url >
Please enter the gitlab-ci token for this runner:
<< token, this is found on the gitlab project page under CI -> Runners >>
Please enter the gitlab-ci description for this runner:
[ENTER]
Please enter the gitlab-ci tags for this runner (comma separated):
skylake2x (or skylake4x etc.)
Registering runner... succeeded                     runner=Dd5n2xcY
Please enter the executor: ssh, virtualbox, docker+machine, kubernetes, docker, docker-ssh, shell, custom, parallels, docker-ssh+machine:
shell
```

In runner settings (Gitlab Web GUI), you can check-mark "Run untagged jobs"
(Indicates whether this runner can pick jobs without tags). If this is needed or
not depends on the `.gitlab-ci.yml` file in the project root. You can also
increase the runner timeout there if necessary (the default is 1h).

Finally, edit `/etc/gitlab-runner/config.toml` to add the machine type
(skylake4x, skylake2x, ryzen5 *etc.*) to the environment of the runner
(`environment` key):

```toml
[[runners]]
  name = "runner-for-skylake4x"
  url = "https://gitlab.com/"
  token = "<< secret token >>"
  executor = "shell"
  environment = ["CI_MACHINE_TYPE=skylake4x"]
```

Make sure to [delete
`~/.bash_logout`](<https://gitlab.com/gitlab-org/gitlab-runner/issues/1379>) to
avoid issues with CI.

## Give access to the benchmark repository

Benchmark results are uploaded automatically to git.

Generate a key for accessing the repository or use an existing key on the
gitlab-runner account:

```bash
ssh-keygen
```

Then, add the key to the `bespin-ci` account.

## Configure software for the gitlab runner account

Install necessary software for use by the runner:

```bash
su gitlab-runner
git clone git@github.com:gz/bespin.git
cd bespin/
bash setup.sh
source $HOME/.cargo/env
sudo adduser gitlab-runner kvm
```

## Disable AppArmor

An annoying security feature that blocks our DHCP server from starting for
testing. You can set-up a rule for allowing this but it's easiest to just get
rid of it on the CI machine:

```bash
sudo systemctl stop apparmor
sudo systemctl disable apparmor
sudo apt remove --assume-yes --purge apparmor
# Unfortunately for apparmor and kvm group changes to take effect, we need to reboot:
sudo reboot
```

## Do a test-run

Verify that the bespin CI script runs without errors (this will take a while):

```bash
CI_MACHINE_TYPE=skylake4x bash scripts/ci.bash
```
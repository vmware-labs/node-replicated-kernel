# CI

We run tests using the gitlab-runner infrastructure. The following steps are
necessary to set-up a new runner machine (and connect a github repo to it).

1. Go to <https://gitlab.com/projects/new>
1. Select tab 'CI/CD for external repo'
1. Click github button
1. Go to <https://github.com/settings/tokens> make a token with the `repo` and `admin:repo_hook` privilege
1. Paste token in gitlab, select repo, click Connect
1. In the gitlab.com project settings go to CI / CD to get the token ID for the setup
1. On the same page, click on 'Disable shared Runners' to not use the gitlab.com pre-configured runner (won't work with our current CI scripts)
1. [Install the gitlab-runner software on a host](#install-gitlab-runner-software-on-a-new-test-machine)
1. [Set-up the software for the gitlab-runner user](#configure-software-for-the-gitlab-runner-account)
1. Register a new runner using `sudo gitlab-runner register` (see above for configuration steps)
1. In github.com Settings tab under Webhooks, change trigger to `push` events only (this avoid CI triggered twice when a pull request is created and
when a push is made to the pull request)
1. Add `id_rsa_bespin.pub` SSH key as a deploy key (github.com repo -> Settings -> Deploy keys), and add the private key as an [Environment variable](#environment-variables)
1. [Delete `~/.bash_logout`](<https://gitlab.com/gitlab-org/gitlab-runner/issues/1379>)

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

Add machine type (skylake4x, skylake2x, ryzen5) through environment of runner to
CI:

```toml
[[runners]]
  name = "bespin-skylake4x"
  url = "https://gitlab.com/"
  token = "RzKskyx5QkyaTPy9xFu3"
  executor = "shell"
  environment = ["CI_MACHINE_TYPE=skylake4x"]
```

## Configure software for the gitlab runner account

Install necessary software for use by the runner:

```bash
su gitlab-runner
curl https://sh.rustup.rs -sSf | sh
source $HOME/.cargo/env
sudo apt-get install -y qemu qemu-kvm uml-utilities mtools qemu-system-x86 isc-dhcp-server socat
cargo install xargo mdbook
```

### Environment variables

Generate a key for accessing the repo or use an existing key:

```bash
ssh-keygen -f .ssh/id_rsa_bespin
```

Add `SSH_PRIVATE_KEY` to key runner and adjust CI file.

```yaml
before_script:
  - 'which ssh-agent || ( apt-get update -y && apt-get install openssh-client -y )'
  - eval $(ssh-agent -s)
  - echo "$SSH_PRIVATE_KEY" | tr -d '\r' | ssh-add -
```

See also:

* <https://docs.gitlab.com/ee/ci/ssh_keys/>
* <https://docs.gitlab.com/ee/ci/variables/README.html#gitlab-cicd-environment-variables>

# CI

### Install gitlab-runner CI software

Install the CI software:

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

Next, create/register a runner (<https://docs.gitlab.com/runner/register/index.html),> it should look like this:

```bash
$ sudo gitlab-runner register

Please enter the gitlab-ci coordinator URL (e.g. https://gitlab.com/):
<< gitlab url >
Please enter the gitlab-ci token for this runner:
<< token >>
Please enter the gitlab-ci description for this runner:
[ENTER]
Please enter the gitlab-ci tags for this runner (comma separated):
skylake2x (or skylake4x etc.)
Registering runner... succeeded                     runner=Dd5n2xcY
Please enter the executor: ssh, virtualbox, docker+machine, kubernetes, docker, docker-ssh, shell, custom, parallels, docker-ssh+machine:
shell
```

In runner settings (Gitlab Web GUI), check-mark "Run untagged jobs" (Indicates whether this runner can pick jobs without tags).
You can also increase the runner timeout there if necessary (the default is 1h).

Add machine type (skylake4x, skylake2x, ryzen5) through environment of runner to CI:

```toml
[[runners]]
  name = "bespin-skylake4x"
  url = "https://gitlab.com/"
  token = "RzKskyx5QkyaTPy9xFu3"
  executor = "shell"
  environment = ["CI_MACHINE_TYPE=skylake4x"]
```

### Configure gitlab runner account

Install necessary software for use by the runner:

```bash
su gitlab-runner
curl https://sh.rustup.rs -sSf | sh
source $HOME/.cargo/env
sudo apt-get install -y qemu qemu-kvm uml-utilities mtools qemu-system-x86 isc-dhcp-server socat
cargo install xargo mdbook
```

### Connect github.com with gitlab.com to run CI on pull requests

1. Go to <https://gitlab.com/projects/new>
2. Select tab 'CI/CD for external repo'
3. Click github button
4. Go to <https://github.com/settings/tokens> make a token with the `repo` and `admin:repo_hook` privilege
5. Paste token in gitlab, select repo, click Connect
6. In the gitlab.com project settings go to CI / CD to get the token ID for the setup
7. On the same page, click on 'Disable shared Runners' to not use the gitlab.com pre-configured runner (won't work with our current CI scripts)
8. Register the runner using `sudo gitlab-runner register` (see above for configuration steps)
9. In github.com Settings tab under Webhooks, change trigger to `push` events only (this avoid CI triggered twice when a pull request is created and
when a push is made to the pull request)
10. Add `id_rsa_bespin.pub` SSH key as a deploy key (github.com repo -> Settings -> Deploy keys), (see also section on Environment variables)
11. Delete `~/.bash_logout` (<https://gitlab.com/gitlab-org/gitlab-runner/issues/1379>)

#### Environment variables

Add `SSH_PRIVATE_KEY` to key runner and adjust CI file.

Generate a key for accessing the repo or use an existing key:

```bash
ssh-keygen -f .ssh/id_rsa_bespin
```

```yaml
before_script:
  - 'which ssh-agent || ( apt-get update -y && apt-get install openssh-client -y )'
  - eval $(ssh-agent -s)
  - echo "$SSH_PRIVATE_KEY" | tr -d '\r' | ssh-add -
```

See also:

* <https://docs.gitlab.com/ee/ci/ssh_keys/>
* <https://docs.gitlab.com/ee/ci/variables/README.html#gitlab-cicd-environment-variables>

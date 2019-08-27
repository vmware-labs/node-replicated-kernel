# Configuration

## Git

Git better usability with submodules:

Update submodules automatically on pull etc.
```
git config --global submodule.recurse true
```

Fetch in parallel:
```
git config --global submodule.fetchJobs 20
```

## Gitlab configuration

### Install gitlab-runner

Install the software (https://docs.gitlab.com/runner/install/linux-manually.html):

Add User

```
sudo useradd --comment 'GitLab Runner' --create-home gitlab --shell /bin/bash
sudo adduser gitlab kvm
visudo
# gitlab  ALL=(ALL) NOPASSWD: ALL
```

Install gitlab-runner:
```
sudo curl -L --output /usr/local/bin/gitlab-runner https://gitlab-runner-downloads.s3.amazonaws.com/latest/binaries/gitlab-runner-linux-amd64
sudo chmod +x /usr/local/bin/gitlab-runner
```

Set-up runner:

```
sudo gitlab-runner uninstall
sudo gitlab-runner install --user=gitlab --working-directory=/home/gitlab
sudo gitlab-runner start
```

Next, register the runner (https://docs.gitlab.com/runner/register/index.html) should look like this:

```
$ sudo gitlab-runner register

Please enter the gitlab-ci coordinator URL (e.g. https://gitlab.com/):
<< gitlab url >
Please enter the gitlab-ci token for this runner:
<< token >>
Please enter the gitlab-ci description for this runner:
[ENTER]
Please enter the gitlab-ci tags for this runner (comma separated):
os,rust
Registering runner... succeeded                     runner=Dd5n2xcY
Please enter the executor: ssh, virtualbox, docker+machine, kubernetes, docker, docker-ssh, shell, custom, parallels, docker-ssh+machine:
shell
```

### Set-up software on gitlab runner account

```
su gitlab
curl https://sh.rustup.rs -sSf | sh
source $HOME/.cargo/env
sudo apt-get install -y qemu qemu-kvm uml-utilities mtools qemu-system-x86 isc-dhcp-server socat
cargo install xargo mdbook
```

### Install webserver
Deprecate this once we have gitlab pages support.

```
su gitlab
cargo install miniserve
sudo vim /etc/systemd/system/bespin-doc.service
```

```
[Unit]
Description=Bespin Documentation

[Service]
User=gitlab
WorkingDirectory=/home/gitlab
ExecStart=/home/gitlab/.cargo/bin/miniserve /home/gitlab/pages-root
SuccessExitStatus=143
TimeoutStopSec=10
Restart=on-failure
RestartSec=5
```

```
sudo systemctl start bespin-doc.service
sudo systemctl status bespin-doc.service
```
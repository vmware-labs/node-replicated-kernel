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

Add User

```
sudo useradd --comment 'GitLab Runner' --create-home gitlab --shell /bin/bash
sudo adduser gitlab kvm
visudo
# gitlab  ALL=(ALL) NOPASSWD: ALL
```

Set-up runner:

```
sudo gitlab-runner uninstall
sudo gitlab-runner install --user=gitlab --working-directory=/home/gitlab
sudo gitlab-runner start
```

### Install webserver
Deprecate this once we have gitlab pages support.

```
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
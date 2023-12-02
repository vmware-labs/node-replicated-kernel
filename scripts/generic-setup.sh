#
# functions to install the build and run dependencies
#

# do we need sudo, or are we already running as root?
if [ ${EUID} != 0 ]; then
    echo "not running as root, using sudo"
    APT="sudo apt-get"
else
    echo "running as root."
    APT="apt-get"
fi


function install_build_dependencies()
{
    echo "installing build dependencies.."
    if [ "$(expr substr $(uname -s) 1 5)" == "Linux" ]; then
        $APT -o Acquire::Max-FutureTime=86400 update > /dev/null

        # installing python build dependencies
        $APT install -y python3 python3-pip python3-plumbum python3-prctl python3-toml python3-pexpect python3-packaging > /dev/null

        # nrk build dependencies
        $APT install -y uml-utilities mtools zlib1g-dev make gcc build-essential git curl > /dev/null

        # For building rump packages (rkapps)
        $APT install -y genisoimage > /dev/null
    fi
}


function install_run_dependencies()
{
    echo "installing run dependencies..."
    if [ "$(uname)" == "Darwin" ]; then
        brew install qemu
    elif [ "$(expr substr $(uname -s) 1 5)" == "Linux" ]; then
        # native build dependencies
        $APT install -y qemu qemu-kvm qemu-system-x86 sshpass hwloc libhwloc-dev numactl libevent-dev bridge-utils > /dev/null

        # nrk integration-test dependencies
        $APT install -y isc-dhcp-server socat netcat-openbsd redis-tools net-tools graphviz tcpdump libhugetlbfs-bin > /dev/null
    fi
}


function bootstrap_rust()
{
    echo "bootstrapping rust..."

    if [ -f "$HOME/.cargo/env" ]; then
        source "$HOME/.cargo/env"
    fi

    # Make sure rust is up-to-date
    if [ ! -x "$(command -v rustup)" ] ; then
        curl https://sh.rustup.rs -sSf | sh -s -- -y
    fi

    source "$HOME/.cargo/env"
    rustup update
}


function install_rust_build_dependencies()
{
    echo "rust build dependencies"

    # Install mdbook (used by docs/)
    if [ ! -x "$(command -v mdbook)" ]; then
        MDBOOK_FLAGS=""
        if [ "$CI" = true ] ; then
            # Reduce compile time by disabling `watch`, `serve` etc. commands
            # otherwise this takes >5min in CI:
            MDBOOK_FLAGS="--no-default-features"
        fi
        cargo install mdbook $MDBOOK_FLAGS --locked --version 0.4.35
    fi
}


function install_rust_run_dependencies()
{
    # Install corealloc (used by run.py) -- only native
    if [ ! -x "$(command -v corealloc)" ]; then
        cargo install corealloc
    fi
}

#
# functions to install the build and run dependencies
#

# the rust version we want
RUST_VERSION=nightly

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

        # installing pytyhon build dependencie
        $APT install -y python3 python3-plumbum python3-prctl python3-toml python3-pexpect > /dev/null

        # bespin build dependencies
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
        $APT install -y qemu qemu-kvm qemu-system-x86 sshpass hwloc libhwloc-dev > /dev/null

        # bespin integration-test dependencies
        $APT install -y isc-dhcp-server socat netcat-openbsd redis-tools net-tools graphviz > /dev/null
    fi
}


function bootstrap_rust()
{
    echo "bootstrapping rust..."

    # nightly-2021-03-16
    if [ -f $HOME/.cargo/env ]; then
        source $HOME/.cargo/env
    fi

    # Make sure rust is up-to-date
    if [ ! -x "$(command -v rustup)" ] ; then
        curl https://sh.rustup.rs -sSf | sh -s -- --default-toolchain ${RUST_VERSION} -y
    fi

    source $HOME/.cargo/env

    # install the desired toolchain
    rustup toolchain install ${RUST_VERSION}
    rustup default ${RUST_VERSION}

    # if running natively, we can just set the version on the kernel directory too
    if [ -d kernel ]; then
        cd kernel
        rustup default ${RUST_VERSION}
        cd ..
    fi

    # add the rust-src
    rustup component add rust-src
    rustup update
}


function install_rust_build_dependencies()
{
    echo "rust build dependencies"

    # Install xargo (used by build)
    if [ ! -x "$(command -v xargo)" ]; then
        cargo install xargo
    fi

    # Install mdbook (used by docs/)
    if [ ! -x "$(command -v mdbook)" ]; then
        cargo install mdbook
    fi
}


function install_rust_run_dependencies()
{
    # Install corealloc (used by run.py) -- only natively
    if [ ! -x "$(command -v corealloc)" ]; then
        cargo install corealloc
    fi
}

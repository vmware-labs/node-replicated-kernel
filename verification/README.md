# Verification experiments

## Setup

Needs a custom version of dafny and lots of code that lives in the verified
betrfs repository:

```bash
git clone https://github.com/vmware-labs/verified-betrfs.git vbtrfs
cd vbtrfs
git checkout concurrency-experiments
./tools/install-dafny.sh
cd ..
```

## Run dafny

```bash
./vbtrfs/.dafny/bin/dafny VSpaceSpec.s.dfy
```

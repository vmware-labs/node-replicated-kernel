#!/bin/bash
#
# Usage: $ CI_MACHINE_TYPE='skylake2x' bash scripts/ci.bash
#
set -ex 

cd kernel
rm -f redis_benchmark.csv
rm -f vmops_benchmark.csv
rm -f vmops_benchmark_latency.csv
rm -f memfs_benchmark.csv

RUST_TEST_THREADS=1 cargo test --test integration-test --features prealloc -- s06_vmops_benchmark --nocapture
RUST_TEST_THREADS=1 cargo test --test integration-test --features prealloc -- s06_vmops_latency_benchmark --nocapture
RUST_TEST_THREADS=1 cargo test --test integration-test -- s06_memfs_bench --nocapture
RUST_TEST_THREADS=1 cargo test --test integration-test -- s06_redis_benchmark_ --nocapture

# Clone repo
rm -rf gh-pages
git clone -b gh-pages bespin-gh-pages:gz/bespin.git gh-pages

# Create CSV entry
export GIT_REV_CURRENT=`git rev-parse --short HEAD`
export CSV_LINE="`date +%Y-%m-%d`",${GIT_REV_CURRENT},"${CI_MACHINE_TYPE}/${GIT_REV_CURRENT}/index.html","${CI_MACHINE_TYPE}/${GIT_REV_CURRENT}/index.html"
echo $CSV_LINE >> gh-pages/_data/$CI_MACHINE_TYPE.csv

# Copy redis results
DEPLOY_DIR="gh-pages/redis/${CI_MACHINE_TYPE}/${GIT_REV_CURRENT}/"
mkdir -p ${DEPLOY_DIR}
cp gh-pages/redis/index.markdown ${DEPLOY_DIR}
mv redis_benchmark.csv ${DEPLOY_DIR}

# Copy vmops results
DEPLOY_DIR="gh-pages/vmops/${CI_MACHINE_TYPE}/${GIT_REV_CURRENT}/"
mkdir -p ${DEPLOY_DIR}
cp gh-pages/vmops/index.markdown ${DEPLOY_DIR}
mv vmops_benchmark.csv ${DEPLOY_DIR}
mv vmops_benchmark_latency.csv ${DEPLOY_DIR}

# Copy memfs results
DEPLOY_DIR="gh-pages/memfs/${CI_MACHINE_TYPE}/${GIT_REV_CURRENT}/"
mkdir -p ${DEPLOY_DIR}
mv memfs_benchmark.csv ${DEPLOY_DIR}

# Push gh-pages
cd gh-pages
git add .
git commit -a -m "Added benchmark results for $GIT_REV_CURRENT."
git push origin gh-pages
cd ..
rm -rf gh-pages
git clean -f

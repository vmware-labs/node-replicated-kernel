#!/bin/bash
#
# Usage: $ CI_MACHINE_TYPE='skylake2x' bash scripts/ci.bash
#
set -ex

cd kernel
rm -f redis_benchmark.csv
rm -f memcached_benchmark.csv
rm -f vmops_benchmark.csv
rm -f vmops_benchmark_latency.csv
rm -f fxmark_benchmark.csv
rm -f leveldb_benchmark.csv

# For vmops: --features prealloc can improve performance further (at the expense of test duration)
RUST_TEST_THREADS=1 cargo test --test integration-test -- s06_vmops_benchmark --nocapture
RUST_TEST_THREADS=1 cargo test --test integration-test -- s06_vmops_latency_benchmark --nocapture
RUST_TEST_THREADS=1 cargo test --test integration-test -- s06_vmops_unmaplat_latency_benchmark --nocapture
RUST_TEST_THREADS=1 cargo test --test integration-test -- s06_redis_benchmark_ --nocapture
#RUST_TEST_THREADS=1 cargo test --test integration-test -- s06_memcached_benchmark --nocapture
RUST_TEST_THREADS=1 cargo test --test integration-test -- s06_leveldb_benchmark --nocapture
RUST_TEST_THREADS=1 cargo test --test integration-test -- s06_fxmark_bench --nocapture

# Clone repo
rm -rf gh-pages
git clone --depth 1 -b master git@github.com:gz/bespin-benchmarks.git gh-pages
pip3 install -r gh-pages/requirements.txt

# If you change this, adjust the command also in the append_csv function in utils.py:
GIT_REV_CURRENT=`git rev-parse --short=8 HEAD`
DATE_PREFIX=`date +"%Y-%m-%d-%H-%M"`

DEPLOY_DIR="gh-pages/redis/${CI_MACHINE_TYPE}/${GIT_REV_CURRENT}/"
if [ -d "${DEPLOY_DIR}" ]; then
    # If we already have results (created the directory),
    # we will add the new results in a subdir
    DEPLOY_DIR=${DEPLOY_DIR}${DATE_PREFIX}
fi
# Copy redis results
mkdir -p ${DEPLOY_DIR}
cp gh-pages/redis/index.markdown ${DEPLOY_DIR}
mv redis_benchmark.csv ${DEPLOY_DIR}
gzip ${DEPLOY_DIR}/redis_benchmark.csv

# Copy memcached results
#DEPLOY_DIR="gh-pages/memcached/${CI_MACHINE_TYPE}/${GIT_REV_CURRENT}/"
#if [ -d "${DEPLOY_DIR}" ]; then
#    # If we already have results (created the directory),
#    # we will add the new results in a subdir
#    DEPLOY_DIR=${DEPLOY_DIR}${DATE_PREFIX}
#fi
#mkdir -p ${DEPLOY_DIR}
#mv memcached_benchmark.csv ${DEPLOY_DIR}
#gzip ${DEPLOY_DIR}/memcached_benchmark.csv

# Copy vmops results
DEPLOY_DIR="gh-pages/vmops/${CI_MACHINE_TYPE}/${GIT_REV_CURRENT}/"
if [ -d "${DEPLOY_DIR}" ]; then
    # If we already have results (created the directory),
    # we will add the new results in a subdir
    DEPLOY_DIR=${DEPLOY_DIR}${DATE_PREFIX}
fi
mkdir -p ${DEPLOY_DIR}
cp gh-pages/vmops/index.markdown ${DEPLOY_DIR}
mv vmops_benchmark.csv ${DEPLOY_DIR}
mv vmops_benchmark_latency.csv ${DEPLOY_DIR}
mv vmops_unmaplat_benchmark_latency.csv ${DEPLOY_DIR}
gzip ${DEPLOY_DIR}/vmops_benchmark.csv
gzip ${DEPLOY_DIR}/vmops_benchmark_latency.csv
gzip ${DEPLOY_DIR}/vmops_unmaplat_benchmark_latency.csv

# Copy memfs results
DEPLOY_DIR="gh-pages/memfs/${CI_MACHINE_TYPE}/${GIT_REV_CURRENT}/"
if [ -d "${DEPLOY_DIR}" ]; then
    # If we already have results (created the directory),
    # we will add the new results in a subdir
    DEPLOY_DIR=${DEPLOY_DIR}${DATE_PREFIX}
fi
mkdir -p ${DEPLOY_DIR}
mv fxmark_benchmark.csv ${DEPLOY_DIR}
gzip ${DEPLOY_DIR}/fxmark_benchmark.csv

#Copy leveldb results
DEPLOY_DIR="gh-pages/leveldb/${CI_MACHINE_TYPE}/${GIT_REV_CURRENT}/"
if [ -d "${DEPLOY_DIR}" ]; then
    # If we already have results (created the directory),
    # we will add the new results in a subdir
    DEPLOY_DIR=${DEPLOY_DIR}${DATE_PREFIX}
fi
mkdir -p ${DEPLOY_DIR}
mv leveldb_benchmark.csv ${DEPLOY_DIR}
gzip ${DEPLOY_DIR}/leveldb_benchmark.csv

# Update CI history plots
python3 gh-pages/_scripts/ci_history.py --append --machine $CI_MACHINE_TYPE

# Push gh-pages
cd gh-pages
if [ "$CI" = true ] ; then
    git config user.email "no-reply@nrkernel.systems"
    git config user.name "bespin-ci"
fi
git add .
git commit -a -m "Added benchmark results for $GIT_REV_CURRENT."
git push origin master
cd ..
rm -rf gh-pages
git clean -f

// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::fs::OpenOptions;
use std::path::Path;

use csv::WriterBuilder;
use rexpect::errors::*;
use rexpect::spawn;
use serde::Serialize;

/// Port we use for the Redis instances.
pub const REDIS_PORT: u16 = 6379;

/// Line we use to tell if Redis has started.
pub const REDIS_START_MATCH: &'static str = "# Server initialized";

/// Binary of the redis benchmark program
pub const REDIS_BENCHMARK: &str = "redis-benchmark";

pub fn redis_benchmark(nic: &'static str, requests: usize) -> Result<rexpect::session::PtySession> {
    fn spawn_bencher(port: u16, requests: usize) -> Result<rexpect::session::PtySession> {
        spawn(
            format!(
                "{} -h 172.31.0.10 -p {} -t ping,get,set -n {} -P 30 --csv",
                REDIS_BENCHMARK, port, requests
            )
            .as_str(),
            Some(45000),
        )
    }

    let mut redis_client = spawn_bencher(REDIS_PORT, requests)?;
    // redis reports the tputs as floating points
    redis_client.exp_string("\"PING_INLINE\",\"")?;
    let (_line, ping_tput) = redis_client.exp_regex("[-+]?[0-9]*\\.?[0-9]+")?;
    redis_client.exp_string("\"")?;

    redis_client.exp_string("\"PING_BULK\",\"")?;
    let (_line, ping_bulk_tput) = redis_client.exp_regex("[-+]?[0-9]*\\.?[0-9]+")?;
    redis_client.exp_string("\"")?;

    redis_client.exp_string("\"SET\",\"")?;
    let (_line, set_tput) = redis_client.exp_regex("[-+]?[0-9]*\\.?[0-9]+")?;
    redis_client.exp_string("\"")?;

    redis_client.exp_string("\"GET\",\"")?;
    let (_line, get_tput) = redis_client.exp_regex("[-+]?[0-9]*\\.?[0-9]+")?;
    redis_client.exp_string("\"")?;

    let ping_tput: f64 = ping_tput.parse().unwrap_or(404.0);
    let ping_bulk_tput: f64 = ping_bulk_tput.parse().unwrap_or(404.0);
    let set_tput: f64 = set_tput.parse().unwrap_or(404.0);
    let get_tput: f64 = get_tput.parse().unwrap_or(404.0);

    // Append parsed results to a CSV file
    let file_name = "redis_benchmark.csv";
    // write headers only to a new file
    let write_headers = !Path::new(file_name).exists();
    let csv_file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(file_name)
        .expect("Can't open file");

    let mut wtr = WriterBuilder::new()
        .has_headers(write_headers)
        .from_writer(csv_file);

    #[derive(Serialize)]
    struct Record {
        git_rev: &'static str,
        ping: f64,
        ping_bulk: f64,
        set: f64,
        get: f64,
        driver: &'static str,
    }

    let record = Record {
        git_rev: env!("GIT_HASH"),
        ping: ping_tput,
        ping_bulk: ping_bulk_tput,
        set: set_tput,
        get: get_tput,
        driver: nic,
    };

    wtr.serialize(record).expect("Can't write results");

    println!("git_rev,nic,ping,ping_bulk,set,get");
    println!(
        "{},{},{},{},{},{}",
        env!("GIT_HASH"),
        nic,
        ping_tput,
        ping_bulk_tput,
        set_tput,
        get_tput
    );
    assert!(
        get_tput > 150_000.0,
        "Redis throughput seems rather low (GET < 200k)?"
    );

    Ok(redis_client)
}

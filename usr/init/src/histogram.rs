// Copyright © 2021 VMware, Inc. All Rights Reserved.
// Copyright © 2017-2020 Brian Martin
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A histogram implementation
//!
//! Original sources from https://github.com/brayniac/histogram -- modified to work with no_std.
//! TODO: Remove this and include histogram = "*" as dependency once there is a std.

#![cfg_attr(feature = "cargo-clippy", deny(missing_docs))]
#![cfg_attr(feature = "cargo-clippy", deny(warnings))]

use alloc::vec;
use alloc::vec::Vec;
use core::{f64, fmt, mem};

use num_traits::Float;

/// A configuration struct for building custom `Histogram`s.
#[derive(Clone, Copy)]
pub struct Config {
    precision: u32,
    max_memory: u32,
    max_value: u64,
    radix: u32,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            precision: 3,
            max_memory: 0,
            max_value: 60_000_000_000,
            radix: 10,
        }
    }
}

impl Config {
    /// create a new Histogram Config with defaults
    ///
    /// # Example
    /// ```
    /// # use histogram::Histogram;
    /// let mut c = Histogram::configure();
    /// ```
    pub fn new() -> Config {
        Default::default()
    }

    /// set HistogramConfig precision
    ///
    /// # Example
    /// ```
    /// # use histogram::Histogram;
    /// let mut c = Histogram::configure();
    /// c.precision(4); // set to 4 significant figures
    /// ```
    pub fn precision(mut self, precision: u32) -> Self {
        self.precision = precision;
        self
    }

    /// set HistogramConfig memory limit
    ///
    /// # Example
    /// ```
    /// # use histogram::Histogram;
    /// let mut c = Histogram::configure();
    /// c.max_memory(1024 * 1024); // cap Histogram at 1MB of data
    /// ```
    pub fn max_memory(mut self, bytes: u32) -> Self {
        self.max_memory = bytes;
        self
    }

    /// set HistogramConfig value limit
    ///
    /// # Example
    /// ```
    /// # use histogram::Histogram;
    /// let mut c = Histogram::configure();
    /// c.max_value(1000); // values above 1000 will not be stored
    /// ```
    pub fn max_value(mut self, max: u64) -> Self {
        self.max_value = max;
        self
    }

    /// Build a new histogram based on the current configuration
    /// values.  Return `None` if the new histogram would require more
    /// than the [configured memory size](#method.max_memory).
    pub fn build(self) -> Option<Histogram> {
        Histogram::configured(self)
    }
}

#[derive(Clone, Copy)]
struct Counters {
    entries_total: u64,
    missed_unknown: u64,
    missed_large: u64,
}

impl Default for Counters {
    fn default() -> Counters {
        Counters {
            entries_total: 0,
            missed_unknown: 0,
            missed_large: 0,
        }
    }
}

impl Counters {
    fn new() -> Counters {
        Default::default()
    }

    fn clear(&mut self) -> &mut Self {
        self.entries_total = 0;
        self.missed_unknown = 0;
        self.missed_large = 0;
        self
    }
}

#[derive(Clone)]
struct Data {
    data: Vec<u64>,
    counters: Counters,
}

#[derive(Clone, Copy)]
struct Properties {
    buckets_inner: u32,
    linear_max: u64,
    linear_power: u32,
}

/// the main datastructure
#[derive(Clone)]
pub struct Histogram {
    config: Config,
    data: Data,
    properties: Properties,
}

/// value-quantized section of `Histogram`
#[derive(Clone, Copy, Debug)]
pub struct Bucket {
    id: u64,
    count: u64,
    value: u64,
    width: u64,
}

impl Bucket {
    /// return the sample value for the bucket
    ///
    /// # Example
    /// ```
    /// # use histogram::Histogram;
    /// let mut h = Histogram::new();
    /// let b = h.into_iter().next().unwrap();
    /// assert_eq!(b.value(), 0);
    /// ```
    pub fn value(self) -> u64 {
        self.value
    }

    /// return the sample counts for the bucket
    ///
    /// # Example
    /// ```
    /// # use histogram::Histogram;
    /// let h = Histogram::new();
    /// let b = h.into_iter().next().unwrap();
    /// assert_eq!(b.count(), 0);
    /// ```
    pub fn count(self) -> u64 {
        self.count
    }

    /// return the bucket id
    ///
    /// # Example
    /// ```
    /// # use histogram::Histogram;
    /// let h = Histogram::new();
    /// let b = h.into_iter().next().unwrap();
    /// assert_eq!(b.id(), 0);
    /// ```
    pub fn id(self) -> u64 {
        self.id
    }

    /// return the width of the bucket
    ///
    /// # Example
    /// ```
    /// # use histogram::Histogram;
    /// let h = Histogram::new();
    /// let b = h.into_iter().next().unwrap();
    /// assert_eq!(b.width(), 1);
    /// ```
    pub fn width(self) -> u64 {
        self.width
    }
}

/// Iterator over a Histogram's buckets.
pub struct Iter<'a> {
    hist: &'a Histogram,
    index: usize,
}

impl<'a> Iter<'a> {
    fn new(hist: &'a Histogram) -> Iter<'a> {
        Iter { hist, index: 0 }
    }
}

impl<'a> Iterator for Iter<'a> {
    type Item = Bucket;

    fn next(&mut self) -> Option<Bucket> {
        let limit = self.hist.get_index(self.hist.config.max_value).unwrap();
        if self.index > limit {
            None
        } else {
            let current = self.index;

            // clamp the value at max value
            let mut value = self.hist.index_value(current);
            if value > self.hist.config.max_value {
                value = self.hist.config.max_value;
                self.index = limit + 1;
            }

            // measure width of current bucket
            let width = if current == 0 {
                1
            } else {
                value - self.hist.index_value(current - 1)
            };
            self.index += 1;
            Some(Bucket {
                id: current as u64,
                count: self.hist.data.data[current],
                value,
                width,
            })
        }
    }
}

impl<'a> IntoIterator for &'a Histogram {
    type Item = Bucket;
    type IntoIter = Iter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        Iter::new(self)
    }
}

impl fmt::Debug for Histogram {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "({} total)", self.data.counters.entries_total)
    }
}

impl Default for Histogram {
    fn default() -> Histogram {
        Config::new().build().unwrap()
    }
}

impl Histogram {
    /// create a new Histogram
    ///
    /// # Example
    /// ```
    /// # use histogram::Histogram;
    /// let mut h = Histogram::new();
    /// ```
    pub fn new() -> Histogram {
        Default::default()
    }

    /// configure a Histogram
    ///
    /// # Example
    /// ```
    /// # use histogram::Histogram;
    /// let mut h = Histogram::configure().max_value(10_000).build().unwrap();
    /// ```
    pub fn configure() -> Config {
        Config::default()
    }

    fn configured(config: Config) -> Option<Histogram> {
        let buckets_inner: u32 = config.radix.pow(config.precision);
        let linear_power: u32 = 32 - buckets_inner.leading_zeros();
        let linear_max: u64 = 2.0_f64.powi(linear_power as i32) as u64;
        let max_value_power: u32 = 64 - config.max_value.leading_zeros();

        let buckets_outer = if max_value_power > linear_power {
            max_value_power - linear_power
        } else {
            0
        };

        let buckets_total = buckets_inner * buckets_outer + linear_max as u32;
        let memory_used = buckets_total * mem::size_of::<u64>() as u32;

        if config.max_memory > 0 && config.max_memory < memory_used {
            return None;
        }

        let data = vec![0; buckets_total as usize];

        let counters = Counters::new();

        Some(Histogram {
            config,
            data: Data { data, counters },
            properties: Properties {
                buckets_inner,
                linear_max,
                linear_power,
            },
        })
    }

    /// clear the histogram data
    ///
    /// # Example
    /// ```
    /// # use histogram::Histogram;
    /// let mut h = Histogram::new();
    ///
    /// h.increment(1);
    /// assert_eq!(h.entries(), 1);
    /// h.clear();
    /// assert_eq!(h.entries(), 0);
    /// ```
    pub fn clear(&mut self) {
        // clear everything manually, weird results in practice?
        self.data.counters.clear();
        for x in &mut self.data.data {
            *x = 0;
        }
    }

    /// increment the count for a value
    ///
    /// # Example
    /// ```
    /// use histogram::Histogram;
    ///
    /// let mut h = Histogram::new();
    ///
    /// h.increment(1);
    /// assert_eq!(h.get(1).unwrap(), 1);
    /// ```
    pub fn increment(&mut self, value: u64) -> Result<(), &'static str> {
        self.increment_by(value, 1_u64)
    }

    /// record additional counts for value
    ///
    /// # Example
    /// ```
    /// # use histogram::Histogram;
    /// let mut h = Histogram::new();
    ///
    /// h.increment_by(1, 1);
    /// assert_eq!(h.get(1).unwrap(), 1);
    ///
    /// h.increment_by(2, 2);
    /// assert_eq!(h.get(2).unwrap(), 2);
    ///
    /// h.increment_by(10, 10);
    /// assert_eq!(h.get(10).unwrap(), 10);
    /// ```
    pub fn increment_by(&mut self, value: u64, count: u64) -> Result<(), &'static str> {
        self.data.counters.entries_total = self.data.counters.entries_total.saturating_add(count);
        if value > self.config.max_value {
            self.data.counters.missed_large = self.data.counters.missed_large.saturating_add(count);
            Err("sample value too large")
        } else {
            match self.get_index(value) {
                Some(index) => {
                    self.data.data[index] = self.data.data[index].saturating_add(count);
                    Ok(())
                }
                None => {
                    self.data.counters.missed_unknown =
                        self.data.counters.missed_unknown.saturating_add(count);
                    Err("sample unknown error")
                }
            }
        }
    }

    /// decrement the count for a value. This functionality is best
    /// used to remove previously inserted from the histogram.
    ///
    /// # Example
    /// ```
    /// # use histogram::Histogram;
    /// let mut h = Histogram::new();
    ///
    /// h.increment(1).unwrap();
    /// assert_eq!(h.get(1).unwrap(), 1);
    /// h.decrement(1).unwrap();
    /// assert_eq!(h.get(1).unwrap(), 0);
    /// ```
    pub fn decrement(&mut self, value: u64) -> Result<(), &'static str> {
        self.decrement_by(value, 1_u64)
    }

    /// remove count for value from histogram. This functionality is
    /// best used to remove previously inserted from the
    /// histogram.
    ///
    /// # Example
    /// ```
    /// # use histogram::Histogram;
    /// let mut h = Histogram::new();
    ///
    /// h.increment_by(1, 1).unwrap();
    /// h.increment_by(2, 2).unwrap();
    /// h.decrement_by(1, 1).unwrap();
    ///
    /// assert_eq!(h.get(2).unwrap(), 2);
    /// assert_eq!(h.get(1).unwrap(), 0);
    /// ```
    pub fn decrement_by(&mut self, value: u64, count: u64) -> Result<(), &'static str> {
        if value > self.config.max_value {
            if let Some(new_missed_large) = self.data.counters.missed_large.checked_sub(count) {
                self.data.counters.missed_large = new_missed_large;
                self.data.counters.entries_total =
                    self.data.counters.entries_total.saturating_sub(count);
                Err("sample value too large")
            } else {
                Err("large sample value underflow")
            }
        } else {
            match self.get_index(value) {
                Some(index) => {
                    if let Some(new_index_value) = self.data.data[index].checked_sub(count) {
                        self.data.data[index] = new_index_value;
                        self.data.counters.entries_total =
                            self.data.counters.entries_total.saturating_sub(count);
                        Ok(())
                    } else {
                        Err("underflow")
                    }
                }
                None => {
                    self.data.counters.missed_unknown =
                        self.data.counters.missed_unknown.saturating_add(count);
                    Err("sample unknown error")
                }
            }
        }
    }

    /// get the count for a value
    ///
    /// # Example
    /// ```
    /// # use histogram::Histogram;
    /// let mut h = Histogram::new();
    /// assert_eq!(h.get(1).unwrap(), 0);
    /// ```
    pub fn get(&self, value: u64) -> Option<u64> {
        match self.get_index(value) {
            Some(index) => Some(self.data.data[index]),
            None => None,
        }
    }

    // calculate the index for a given value
    fn get_index(&self, value: u64) -> Option<usize> {
        if value <= (self.properties.linear_max + 2_u64.pow(self.config.precision)) {
            return Some(value as usize);
        }

        let l_max = self.properties.linear_max as u32;

        let outer = 63 - value.leading_zeros();

        let l_power = 63 - self.properties.linear_max.leading_zeros();

        let remain = value as f64 - 2.0_f64.powi(outer as i32);

        let inner = (f64::from(self.properties.buckets_inner) * remain as f64
            / 2.0_f64.powi((outer) as i32))
        .floor() as u32;

        // this gives the shifted outer index
        let outer = outer as u32 - l_power;

        let index = l_max + self.properties.buckets_inner * outer + inner + 1;

        Some(index as usize)
    }

    // calculate the nominal value of the given index
    fn index_value(&self, index: usize) -> u64 {
        // in this case, the index is linear
        let index = index as u32;

        let linear_max = self.properties.linear_max as u32;

        if index <= linear_max {
            return u64::from(index);
        }

        let log_index = index - linear_max;

        let outer =
            (f64::from(log_index) / f64::from(self.properties.buckets_inner)).floor() as u32;

        let inner = log_index - outer * self.properties.buckets_inner as u32;

        let mut value = 2.0_f64.powi((outer as u32 + self.properties.linear_power) as i32);
        value += f64::from(inner) * (value as f64 / f64::from(self.properties.buckets_inner));

        if value > self.config.max_value as f64 {
            return self.config.max_value as u64;
        }
        value.ceil() as u64
    }

    /// return the value for the given percentile
    ///
    /// # Example
    /// ```
    /// # use histogram::Histogram;
    /// let mut h = Histogram::new();
    /// for value in 1..1000 {
    ///     h.increment(value).unwrap();
    /// }
    ///
    /// assert_eq!(h.percentile(50.0).unwrap(), 501);
    /// assert_eq!(h.percentile(90.0).unwrap(), 901);
    /// assert_eq!(h.percentile(99.0).unwrap(), 991);
    /// assert_eq!(h.percentile(99.9).unwrap(), 999);
    /// ```
    pub fn percentile(&self, percentile: f64) -> Result<u64, &'static str> {
        if self.entries() < 1 {
            return Err("no data");
        }

        if percentile <= 100.0 && percentile >= 0.0 {
            let total = self.entries();

            let mut need = (total as f64 * (percentile / 100.0_f64)).ceil() as u64;

            if need > total {
                need = total;
            }

            need = total - need;

            let mut index: isize = (self.buckets_total() - 1) as isize;
            let mut step: isize = -1 as isize;

            let mut have = if percentile < 50.0 {
                index = 0 as isize;
                step = 1 as isize;
                need = total - need;
                0
            } else {
                self.data.counters.missed_large
            };

            if need == 0 {
                need = 1;
            }

            if have >= need {
                if index == 0 {
                    return Err("underflow");
                }
                return Err("overflow");
            }
            loop {
                have += self.data.data[index as usize];

                if have >= need {
                    return Ok(self.index_value(index as usize) as u64);
                }

                index += step;

                if index >= self.buckets_total() as isize {
                    break;
                }
                if index < 0 {
                    break;
                }
            }
        }
        Err("unknown failure")
    }

    /// convenience function for min
    ///
    /// # Example
    /// ```
    /// # use histogram::Histogram;
    /// let mut h = Histogram::new();
    /// for value in 1..1000 {
    ///     h.increment(value);
    /// }
    /// assert_eq!(h.minimum().unwrap(), 1);
    /// ```
    pub fn minimum(&self) -> Result<u64, &'static str> {
        self.percentile(0.0_f64)
    }

    /// convenience function for max
    ///
    /// # Example
    /// ```
    /// # use histogram::Histogram;
    /// let mut h = Histogram::new();
    /// for value in 1..1000 {
    ///     h.increment(value);
    /// }
    /// assert_eq!(h.maximum().unwrap(), 999);
    /// ```
    pub fn maximum(&self) -> Result<u64, &'static str> {
        self.percentile(100.0_f64)
    }

    /// arithmetic mean approximation across the histogram
    ///
    /// # Example
    /// ```
    /// # use histogram::Histogram;
    /// let mut h = Histogram::new();
    /// for value in 1..1000 {
    ///     h.increment(value);
    /// }
    /// assert_eq!(h.mean().unwrap(), 500);
    /// ```
    pub fn mean(&self) -> Result<u64, &'static str> {
        if self.entries() < 1 {
            return Err("no data");
        }

        let total = self.entries();

        let mut mean = 0.0_f64;

        for index in 0..(self.buckets_total() as usize) {
            mean += (self.index_value(index) as f64 * self.data.data[index] as f64) as f64
                / total as f64;
        }
        Ok(mean.ceil() as u64)
    }

    /// standard variance approximation across the histogram
    ///
    /// # Example
    /// ```
    /// # use histogram::Histogram;
    /// let mut h = Histogram::new();
    /// for value in 1..11 {
    ///     h.increment(value);
    /// }
    /// assert_eq!(h.stdvar().unwrap(), 9);
    /// ```
    pub fn stdvar(&self) -> Result<u64, &'static str> {
        if self.entries() < 1 {
            return Err("no data");
        }

        let total = self.entries() as f64;

        let m = self.mean().unwrap() as f64;

        let mut stdvar = 0.0_f64;

        for index in 0..(self.buckets_total() as usize) {
            let v = self.index_value(index) as f64;
            let c = self.data.data[index] as f64;
            stdvar += (c * v * v) - (2_f64 * c * m * v) + (c * m * m);
        }

        stdvar /= total;

        Ok(stdvar.ceil() as u64)
    }

    /// standard deviation approximation across the histogram
    ///
    /// # Example
    /// ```
    /// # use histogram::Histogram;
    /// let mut h = Histogram::new();
    ///
    /// for value in 1..11 {
    ///     h.increment(value);
    /// }
    ///
    /// assert_eq!(h.stddev().unwrap(), 3);
    ///
    /// h.clear();
    ///
    /// for value in 1..4 {
    ///     h.increment(value);
    /// }
    /// for _ in 0..26 {
    ///     h.increment(1);
    /// }
    ///
    /// assert_eq!(h.stddev().unwrap(), 1);
    /// ```
    pub fn stddev(&self) -> Option<u64> {
        if self.entries() < 1 {
            return None;
        }

        let stdvar = self.stdvar().unwrap() as f64;
        let stddev = stdvar.sqrt();

        Some(stddev.ceil() as u64)
    }

    /// merge one Histogram into another Histogram
    ///
    /// # Example
    /// ```
    /// # use histogram::Histogram;
    /// let mut a = Histogram::new();
    /// let mut b = Histogram::new();
    ///
    /// assert_eq!(a.entries(), 0);
    /// assert_eq!(b.entries(), 0);
    ///
    /// a.increment(1);
    /// b.increment(2);
    ///
    /// assert_eq!(a.entries(), 1);
    /// assert_eq!(b.entries(), 1);
    ///
    /// a.merge(&mut b);
    ///
    /// assert_eq!(a.entries(), 2);
    /// assert_eq!(a.get(1).unwrap(), 1);
    /// assert_eq!(a.get(2).unwrap(), 1);
    /// ```
    pub fn merge(&mut self, other: &Histogram) {
        for bucket in other {
            let _ = self.increment_by(bucket.value, bucket.count);
        }
    }

    /// return the number of entries in the Histogram
    ///
    /// # Example
    /// ```
    /// # use histogram::Histogram;
    /// let mut h = Histogram::new();
    ///
    /// assert_eq!(h.entries(), 0);
    /// h.increment(1);
    /// assert_eq!(h.entries(), 1);
    /// ```
    pub fn entries(&self) -> u64 {
        self.data.counters.entries_total
    }

    /// return the number of buckets in the Histogram
    ///
    /// # Example
    /// ```
    /// # use histogram::Histogram;
    /// let mut h = Histogram::new();
    ///
    /// assert!(h.buckets_total() > 1);
    /// ```
    pub fn buckets_total(&self) -> u64 {
        (self.get_index(self.config.max_value).unwrap() + 1) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::Histogram;

    #[test]
    fn test_too_large() {
        let h = Histogram::configure()
            .max_value(10_000)
            .precision(3)
            .max_memory(8192)
            .build();

        if let Some(_) = h {
            panic!("Created histogram which used too much memory");
        }
    }

    #[test]
    fn test_increment_0() {
        let mut h = Histogram::new();

        for op in 1..1000000 {
            h.increment(1).unwrap();
            assert_eq!(h.entries(), op);
        }
    }

    #[test]
    fn test_increment_1() {
        let mut h = Histogram::configure()
            .max_value(10)
            .precision(3)
            .build()
            .unwrap();

        // increment values across the entire range
        // including 0 and max_value
        for v in 0..11 {
            h.increment(v).unwrap();
            assert_eq!(h.entries(), v + 1);
        }
    }

    #[test]
    fn test_decrement_0() {
        let mut h = Histogram::new();
        let m = 1000000;

        for _ in 0..m {
            h.increment(2).unwrap();
        }

        for op in 1..m {
            h.decrement(2).unwrap();
            assert_eq!(h.entries(), m - op);
        }
    }

    #[test]
    fn test_decrement_1() {
        let mut h = Histogram::configure()
            .max_value(20_000)
            .precision(3)
            .build()
            .unwrap();

        let v = h.properties.linear_max + 2;
        let m = 1_000_000;

        for _ in 0..m {
            h.increment(v).unwrap();
        }

        for op in 1..m {
            h.decrement(v).unwrap();
            assert_eq!(h.entries(), m - op);
        }
    }

    #[test]
    #[should_panic(expected = "large sample value underflow")]
    fn test_decrement_4() {
        let mut h = Histogram::new();
        let v = h.config.max_value + 1;
        h.decrement(v).unwrap();
    }

    #[test]
    #[should_panic(expected = "sample value too large")]
    fn test_decrement_5() {
        let mut h = Histogram::new();
        let v = h.config.max_value + 1;
        let _ = h.increment(v);
        h.decrement(v).unwrap();
    }

    #[test]
    fn test_decrement_example_0() {
        let mut h = Histogram::new();

        h.increment(1).unwrap();
        assert_eq!(h.get(1).unwrap(), 1);
        h.decrement(1).unwrap();
        assert_eq!(h.get(1).unwrap(), 0);
    }

    #[test]
    fn test_decrement_by_example_0() {
        let mut h = Histogram::new();

        h.increment_by(1, 1).unwrap();
        h.increment_by(2, 2).unwrap();
        h.decrement_by(1, 1).unwrap();

        assert_eq!(h.get(2).unwrap(), 2);
        assert_eq!(h.get(1).unwrap(), 0);
    }

    #[test]
    fn test_get() {
        let mut h = Histogram::new();

        h.increment(1).unwrap();
        assert_eq!(h.get(1), Some(1));

        h.increment(1).unwrap();
        assert_eq!(h.get(1), Some(2));

        h.increment(2).unwrap();
        assert_eq!(h.get(2), Some(1));

        assert_eq!(h.get(3), Some(0));
    }

    #[test]
    fn test_get_index_0() {
        let h = Histogram::configure()
            .max_value(32)
            .precision(3)
            .build()
            .unwrap();

        // all values should index directly to value
        // no estimated buckets are needed given the precision and max
        for i in 0..32 {
            assert_eq!(h.get_index(i), Some(i as usize));
            assert_eq!(h.index_value(i as usize), i);
        }
    }

    #[test]
    fn test_index_value_0() {
        let h = Histogram::configure()
            .max_value(100)
            .precision(1)
            .build()
            .unwrap();

        assert_eq!(h.index_value(1), 1);
        assert_eq!(h.index_value(2), 2);
        assert_eq!(h.index_value(15), 15);

        assert_eq!(h.index_value(16), 16);
        assert_eq!(h.index_value(26), 32);
        assert_eq!(h.index_value(36), 64);
    }

    #[test]
    fn test_index_value_1() {
        let h = Histogram::configure()
            .max_value(1_000)
            .precision(2)
            .build()
            .unwrap();

        assert_eq!(h.index_value(0), 0);
        assert_eq!(h.index_value(1), 1);
        assert_eq!(h.index_value(126), 126);

        assert_eq!(h.index_value(128), 128);
        assert_eq!(h.index_value(228), 256);
        assert_eq!(h.index_value(328), 512);
    }

    #[test]
    fn test_index_value_2() {
        let h = Histogram::configure()
            .max_value(10_000)
            .precision(3)
            .build()
            .unwrap();

        assert_eq!(h.index_value(0), 0);
        assert_eq!(h.index_value(1), 1);
        assert_eq!(h.index_value(1023), 1023);

        assert_eq!(h.index_value(1024), 1024);
        assert_eq!(h.index_value(2024), 2048);
    }

    #[test]
    fn test_iterator() {
        let h = Histogram::configure()
            .max_value(100)
            .precision(1)
            .build()
            .unwrap();

        let mut buckets_seen = 0;
        for bucket in &h {
            println!("Bucket: {:?}", bucket);
            assert_eq!(bucket.id(), buckets_seen);
            assert_eq!(bucket.value(), h.index_value(bucket.id() as usize));
            assert_eq!(bucket.count(), 0);
            buckets_seen += 1;
        }
        assert_eq!(h.buckets_total(), buckets_seen);
    }

    #[test]
    fn test_percentile() {
        let mut h = Histogram::configure()
            .max_value(1_000)
            .precision(4)
            .build()
            .unwrap();

        for i in 100..200 {
            h.increment(i).ok().expect("error");
        }

        assert_eq!(h.percentile(0.0).unwrap(), 100);
        assert_eq!(h.percentile(10.0).unwrap(), 109);
        assert_eq!(h.percentile(25.0).unwrap(), 124);
        assert_eq!(h.percentile(50.0).unwrap(), 150);
        assert_eq!(h.percentile(75.0).unwrap(), 175);
        assert_eq!(h.percentile(90.0).unwrap(), 190);
        assert_eq!(h.percentile(95.0).unwrap(), 195);
        assert_eq!(h.percentile(100.0).unwrap(), 199);
    }

    #[test]
    fn test_percentile_bad() {
        let mut h = Histogram::configure()
            .max_value(1_000)
            .precision(4)
            .build()
            .unwrap();

        let _ = h.increment(5_000);

        assert!(h.percentile(0.0).is_err());
        assert!(h.percentile(50.0).is_err());
        assert!(h.percentile(100.0).is_err());

        let _ = h.increment(1);

        assert!(h.percentile(0.0).is_ok());

        let _ = h.increment(500);
        let _ = h.increment(500);

        assert!(h.percentile(50.0).is_ok());
    }

    #[test]
    fn test_width_1() {
        let mut h = Histogram::configure()
            .max_value(100)
            .precision(3)
            .build()
            .unwrap();

        for v in 0..101 {
            let _ = h.increment(v);
        }

        assert_eq!(h.data.counters.missed_large, 0);

        let mut prev_id = 0;
        for b in &h {
            println!("Bucket: {:?}", b);
            if b.id() >= 1 {
                assert!(b.id() - 1 == prev_id);
                prev_id = b.id();
            }
            assert!(b.width() != 0, "width should not be 0");
            assert_eq!(b.width(), b.count());
        }
    }

    #[test]
    fn test_width_2() {
        let mut h = Histogram::configure()
            .max_value(1000)
            .precision(2)
            .build()
            .unwrap();

        for v in 0..1001 {
            let _ = h.increment(v);
        }

        assert_eq!(h.data.counters.missed_large, 0);

        let mut prev_id = 0;
        let mut prev_value = 0;
        for b in &h {
            println!("Bucket: {:?}", b);
            if b.id() >= 1 {
                assert_eq!(b.width(), b.value() - prev_value);
                assert!(b.id() - 1 == prev_id);
                prev_id = b.id();
                prev_value = b.value();
            }
            assert!(b.width() != 0, "width should not be 0");
        }
    }
    #[test]
    fn test_width_3() {
        let mut h = Histogram::configure()
            .max_value(10_000)
            .precision(3)
            .build()
            .unwrap();

        for v in 0..10_000 {
            let _ = h.increment(v + 1);
        }

        assert_eq!(h.data.counters.missed_large, 0);

        let mut prev_id = 0;
        let mut prev_value = 0;
        for b in &h {
            println!("Bucket: {:?}", b);
            if b.id() >= 1 {
                assert_eq!(b.width(), b.value() - prev_value);
                assert!(b.id() - 1 == prev_id);
                prev_id = b.id();
                prev_value = b.value();
            }
            assert!(b.width() != 0, "width should not be 0");
        }
    }
}

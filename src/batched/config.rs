use murmur::batched::BatchedMurmurConfig;

use serde::{Deserialize, Serialize};

#[cfg(feature = "cli")]
use structopt::StructOpt;

#[cfg_attr(feature = "cli", derive(StructOpt))]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
/// Configuration struct for `BatchedSieve`
pub struct BatchedSieveConfig {
    #[cfg_attr(feature = "cli", structopt(flatten))]
    /// Configuration for the underlying `BatchedMurmur` used
    pub murmur: BatchedMurmurConfig,

    /// Threshold of echoes required to consider some payload valid
    #[cfg_attr(feature = "cli", structopt(long, short))]
    pub threshold: usize,

    /// Expected size of echo set when sampling
    #[cfg_attr(feature = "cli", structopt(long, short))]
    pub expected: usize,
}

impl BatchedSieveConfig {
    /// Get the inner murmur configuration
    pub fn murmur(&self) -> &BatchedMurmurConfig {
        &self.murmur
    }

    /// Get the echo threshold
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Check if the  given argument is greater or equal to the threshold
    pub fn threshold_cmp(&self, have: i32) -> bool {
        have >= self.threshold as i32
    }

    /// Get expected size of echo set of peers
    pub fn expected(&self) -> usize {
        self.expected
    }
}

impl Default for BatchedSieveConfig {
    fn default() -> Self {
        Self {
            murmur: BatchedMurmurConfig::default(),
            threshold: 10,
            expected: 10,
        }
    }
}

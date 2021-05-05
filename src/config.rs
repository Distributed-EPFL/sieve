use std::time::Duration;

use murmur::MurmurConfig;

use serde::{Deserialize, Serialize};

use derive_builder::Builder;

#[cfg(feature = "cli")]
use structopt::StructOpt;

#[cfg_attr(feature = "cli", derive(StructOpt))]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Builder)]
/// Configuration struct for [`Sieve`]
///
/// [`Sieve`]: super::Sieve
pub struct SieveConfig {
    #[cfg_attr(feature = "cli", structopt(flatten))]
    /// Configuration for the underlying [`Murmur`] used
    ///
    /// [`Murmur`]: murmur::Murmur
    pub murmur: MurmurConfig,

    /// Threshold of echoes required to consider some payload valid
    #[cfg_attr(feature = "cli", structopt(long, short))]
    pub echo_threshold: usize,

    /// Expected size of echo set when sampling
    #[cfg_attr(feature = "cli", structopt(long))]
    pub sieve_sample_size: usize,
}

impl SieveConfig {
    /// Check if the  given argument is greater or equal to the threshold
    pub fn threshold_cmp(&self, have: i32) -> bool {
        have >= self.echo_threshold as i32
    }

    /// Get the expiration delay for delivered batches
    pub fn expiration_delay(&self) -> Duration {
        self.murmur.batch_expiration()
    }

    /// Get the channel capacity for this configuration
    pub fn channel_cap(&self) -> usize {
        self.murmur.channel_cap
    }
}

impl Default for SieveConfig {
    fn default() -> Self {
        Self {
            murmur: MurmurConfig::default(),
            echo_threshold: 10,
            sieve_sample_size: 10,
        }
    }
}

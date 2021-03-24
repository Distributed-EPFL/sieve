use super::*;

use std::collections::BTreeSet;
use std::fmt;

use futures::{Stream, StreamExt};

/// A view of a `Batch` that  filters out `Payload`s that haven't received sufficient echoes
/// from other peers
#[derive(Clone)]
pub struct FilteredBatch<M: Message> {
    batch: Arc<Batch<M>>,
    included: BTreeSet<Sequence>,
}

impl<M> FilteredBatch<M>
where
    M: Message,
{
    /// Create a new `FilteredBatch` using an `Iterator` of excluded `Sequence`s
    pub fn new(batch: Arc<Batch<M>>, include: impl IntoIterator<Item = Sequence>) -> Self {
        Self {
            batch,
            included: include.into_iter().collect(),
        }
    }

    /// Create a new `FilteredBatch` from a `Stream` of excluded payloads
    pub async fn new_async(batch: Arc<Batch<M>>, inclusions: impl Stream<Item = Sequence>) -> Self {
        Self {
            batch,
            included: inclusions.collect().await,
        }
    }

    /// Get the `Digest` from this `FilteredBatch`
    pub fn digest(&self) -> &Digest {
        &self.batch.info().digest()
    }

    /// Check if it is worth delivering this `FilteredBatch`
    pub fn deliverable(&self) -> bool {
        !self.included.is_empty()
    }

    /// Get the length of this `FilteredBatch`
    pub fn len(&self) -> usize {
        self.included.len()
    }

    /// Check if this `FilteredBatch` contains any `Payload`s
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get the list of excluded `Sequence`s in this `FilteredBatch`
    pub fn included(&self) -> impl Iterator<Item = Sequence> + '_ {
        self.included.iter().copied()
    }

    /// Number of excluded payloads in this `FilteredBatch`
    pub fn excluded_len(&self) -> usize {
        self.batch.info().size() - self.included.len()
    }

    /// Get the total length of this `FilteredBatch` as a `Sequence`
    pub fn sequence(&self) -> Sequence {
        self.batch.info().sequence()
    }

    /// Merge the given `FilteredBatch` with this one
    pub fn merge(&mut self, mut other: Self) {
        self.included.append(&mut other.included);
    }

    /// Create a new `FilteredBatch` that excludes both excluded `Sequence` from this `FilteredBatch` as well as
    /// the provided `Sequence`s
    pub fn exclude(&self, range: impl IntoIterator<Item = Sequence>) -> Self {
        Self {
            batch: self.batch.clone(),
            included: self
                .included
                .difference(&range.into_iter().collect())
                .copied()
                .collect(),
        }
    }

    /// Get an `Iterator` of all valid `Payload`s in this `FilteredBatch`
    pub fn iter(&self) -> impl Iterator<Item = &Payload<M>> {
        self.batch
            .iter()
            .filter(move |x| self.included.contains(&x.sequence()))
    }
}

impl<M> fmt::Display for FilteredBatch<M>
where
    M: Message,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} including {} payloads",
            self.batch.info(),
            self.included.len()
        )
    }
}

impl<M> fmt::Debug for FilteredBatch<M>
where
    M: Message,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.batch.info())
    }
}

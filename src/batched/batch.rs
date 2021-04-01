use super::*;

use std::collections::BTreeSet;
use std::fmt;

/// A view of a `Batch` that  filters out `Payload`s that haven't received sufficient echoes
/// from other peers
#[derive(Clone)]
pub struct FilteredBatch<M: Message> {
    batch: Arc<Batch<M>>,
    excluded: BTreeSet<Sequence>,
}

impl<M> FilteredBatch<M>
where
    M: Message,
{
    /// Create a  new `FilteredBatch` using a list of excluded Sequence
    pub fn new(batch: Arc<Batch<M>>, exclude: impl IntoIterator<Item = Sequence>) -> Self {
        let excluded = exclude
            .into_iter()
            .filter(|x| *x < batch.info().sequence())
            .collect();

        Self { batch, excluded }
    }

    /// Create new `FilteredBatch` from a list of included sequences
    pub fn with_inclusion(batch: Arc<Batch<M>>, include: &BTreeSet<Sequence>) -> Self {
        let excluded = (0..batch.info().sequence())
            .filter(|x| !include.contains(&x))
            .collect();

        Self { batch, excluded }
    }

    /// Get the `Digest` from this `FilteredBatch`
    pub fn digest(&self) -> &Digest {
        &self.batch.info().digest()
    }

    /// Check if it is worth delivering this `FilteredBatch`
    pub fn deliverable(&self) -> bool {
        !self.is_empty()
    }

    /// Get the length of this `FilteredBatch`
    pub fn len(&self) -> usize {
        self.batch.info().size() - self.excluded.len()
    }

    /// Check if this `FilteredBatch` contains any `Payload`s
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get the list of excluded `Sequence`s in this `FilteredBatch`
    pub fn included<'a>(&'a self) -> impl Iterator<Item = Sequence> + 'a {
        (0..self.len() as Sequence).filter(move |x| !self.excluded.contains(&x))
    }

    /// Number of excluded payloads in this `FilteredBatch`
    pub fn excluded_len(&self) -> usize {
        self.excluded.len()
    }

    /// Get the total length of this `FilteredBatch` as a `Sequence`
    pub fn sequence(&self) -> Sequence {
        self.batch.info().sequence()
    }

    /// Merge the given `FilteredBatch` with this one
    pub fn merge(&mut self, other: Self) {
        self.excluded = self
            .excluded
            .intersection(&other.excluded)
            .copied()
            .collect();
    }

    /// Create a new `FilteredBatch` that excludes both excluded `Sequence` from this `FilteredBatch` as well as
    /// the provided `Sequence`s
    pub fn exclude(&self, range: impl IntoIterator<Item = Sequence>) -> Self {
        let mut excluded = self.excluded.clone();

        excluded.extend(range);

        Self {
            batch: self.batch.clone(),
            excluded,
        }
    }

    /// Make a new `FilteredBatch` that only contains the specfified set of `Sequence`s
    /// from this `FilteredBatch`
    pub fn include(&self, range: impl IntoIterator<Item = Sequence>) -> Self {
        Self::new(self.batch.clone(), range)
    }

    /// Get an `Iterator` of all valid `Payload`s in this `FilteredBatch`
    pub fn iter(&self) -> impl Iterator<Item = &Payload<M>> {
        self.batch
            .iter()
            .filter(move |x| !self.excluded.contains(&x.sequence()))
    }
}

impl<M> fmt::Display for FilteredBatch<M>
where
    M: Message,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} excluding {} payloads",
            self.batch.info(),
            self.excluded.len()
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

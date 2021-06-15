use super::*;

use std::collections::BTreeSet;
use std::fmt;
use std::iter;

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

    /// Get the [`BatchInfo`] for this `FilteredBatch`
    pub fn info(&self) -> &BatchInfo {
        self.batch.info()
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

    /// Get an `Iterator` of sequences excluded from this `FilteredBatch`
    pub fn excluded(&self) -> impl Iterator<Item = Sequence> + '_ {
        self.excluded.iter().copied()
    }

    /// Get the list of excluded `Sequence`s in this `FilteredBatch`
    pub fn included(&self) -> impl Iterator<Item = Sequence> + '_ {
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

        Self::new(self.batch.clone(), excluded)
    }

    /// Make a new `FilteredBatch` that only contains the specfified set of `Sequence`s
    /// from this `FilteredBatch`
    pub fn include(&self, range: impl IntoIterator<Item = Sequence>) -> Self {
        let new = range.into_iter().collect::<BTreeSet<_>>();

        Self::new(
            self.batch.clone(),
            (0..self.sequence()).filter(|x| !new.contains(x)),
        )
    }

    /// Make a new `FilteredBatch` that only contains the specified set of `Sequence`
    pub async fn include_stream(&self, range: impl Stream<Item = Sequence>) -> Self {
        let included = range.collect::<BTreeSet<_>>().await;

        Self::new(
            self.batch.clone(),
            (0..self.batch.info().sequence()).filter(|x| !included.contains(&x)),
        )
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

impl<M> From<&TimedBatch<M>> for FilteredBatch<M>
where
    M: Message,
{
    fn from(batch: &TimedBatch<M>) -> Self {
        Self::new(batch.into(), iter::empty())
    }
}

use super::*;

use std::fmt;

use futures::{Stream, StreamExt};

/// A view of a `Batch` that  filters out `Payload`s that haven't received sufficient echoes
/// from other peers
#[derive(Clone)]
pub struct FilteredBatch<M: Message> {
    batch: Arc<Batch<M>>,
    excluded: Vec<Sequence>,
}

impl<M> FilteredBatch<M>
where
    M: Message,
{
    /// Create a new `FilteredBatch` using an `Iterator` of excluded `Sequence`s
    pub fn new(batch: Arc<Batch<M>>, exclusions: impl IntoIterator<Item = Sequence>) -> Self {
        Self {
            batch,
            excluded: exclusions.into_iter().collect(),
        }
    }

    /// Check if it is worth delivering this `FilteredBatch`
    pub fn deliverable(&self) -> bool {
        !self.excluded.is_empty()
    }

    /// Get the list of excluded `Sequence`s in this `FilteredBatch`
    pub fn excluded(&self) -> &[Sequence] {
        &self.excluded
    }

    /// Number of excluded payloads in this `FilteredBatch`
    pub fn excluded_len(&self) -> usize {
        self.excluded().len()
    }

    /// Create a new `FilteredBatch` from a `Stream` of excluded payloads
    pub async fn new_async(batch: Arc<Batch<M>>, exclusions: impl Stream<Item = Sequence>) -> Self {
        Self {
            batch,
            excluded: exclusions.collect().await,
        }
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
            "{} with {} exclusions",
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

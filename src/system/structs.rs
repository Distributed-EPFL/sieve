use std::{
    ops::Deref,
    sync::Arc,
    time::{Duration, Instant},
};

use super::{Batch, Message};

pub struct TimedBatch<M>
where
    M: Message,
{
    time: Instant,
    batch: Arc<Batch<M>>,
}

impl<M> TimedBatch<M>
where
    M: Message,
{
    pub fn is_expired(&self, duration: Duration) -> bool {
        Instant::now().duration_since(self.time) >= duration
    }
}

impl<M> Deref for TimedBatch<M>
where
    M: Message,
{
    type Target = Batch<M>;

    fn deref(&self) -> &Self::Target {
        self.batch.deref()
    }
}

impl<M> From<Arc<Batch<M>>> for TimedBatch<M>
where
    M: Message,
{
    fn from(batch: Arc<Batch<M>>) -> Self {
        Self {
            time: Instant::now(),
            batch,
        }
    }
}

impl<M> From<&TimedBatch<M>> for Arc<Batch<M>>
where
    M: Message,
{
    fn from(timed: &TimedBatch<M>) -> Self {
        timed.batch.clone()
    }
}

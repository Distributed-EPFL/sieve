use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, HashMap};
use std::pin::Pin;

use super::{BatchInfo, Digest, Sequence};

use futures::future::FutureExt;
use futures::stream::{self, Stream, StreamExt};

use tokio::sync::{mpsc, oneshot, RwLock};
use tokio::task::{self, JoinHandle};

use tokio_stream::wrappers::ReceiverStream;

use tracing::{debug, debug_span, error, info, trace, warn};
use tracing_futures::Instrument;

#[derive(Copy, Clone, Debug)]
enum State {
    Seen,
    Delivered,
}

impl State {
    fn set_delivered(&mut self) -> bool {
        if let Self::Seen = self {
            *self = Self::Delivered;
            true
        } else {
            false
        }
    }
}

type Channel = oneshot::Sender<Sequence>;

/// Handle for the agent that keeps track of which payloads have been seen and/or delivered for each known batch
pub struct SeenHandle {
    senders: RwLock<HashMap<Digest, mpsc::Sender<Command>>>,
    capacity: usize,
}

impl SeenHandle {
    /// Create a new `PendingHandle` using a given channel capacity
    pub fn new(capacity: usize) -> Self {
        Self {
            senders: Default::default(),
            capacity,
        }
    }

    async fn register(
        &self,
        digest: Digest,
        sequences: impl Stream<Item = Sequence>,
        maker: impl Fn(Sequence, oneshot::Sender<Sequence>) -> Command + Copy,
    ) -> impl Stream<Item = Sequence> {
        let tx = self.get_agent_or_insert(digest).await;

        sequences
            .zip(stream::repeat(tx))
            .filter_map(move |(seq, tx)| async move {
                let (resp, rx) = oneshot::channel();
                let command = (maker)(seq, resp);

                if tx.send(command).await.is_err() {
                    error!("agent for batch {} stopped running", digest);
                }

                rx.await.ok()
            })
    }

    /// Register a `Stream` of sequences as seen and returns the ones that weren't already seen or delivered
    pub async fn register_seen(
        &self,
        digest: Digest,
        sequences: impl Stream<Item = Sequence>,
    ) -> impl Stream<Item = Sequence> {
        self.register(digest, sequences, Command::Seen).await
    }

    /// Register a `Stream` of sequences as delivered and returns a stream of sequences
    /// that were previously seen but not already delivered
    pub async fn register_delivered(
        &self,
        digest: Digest,
        sequences: impl Stream<Item = Sequence>,
    ) -> impl Stream<Item = Sequence> {
        self.register(digest, sequences, Command::Delivered).await
    }

    /// Register delivery for an Iterator of sequences and returns a Stream of sequences that were not already delivered
    pub async fn register_delivered_iter(
        &self,
        digest: Digest,
        seqs: impl IntoIterator<Item = Sequence>,
    ) -> impl Stream<Item = Sequence> {
        self.register_delivered(digest, stream::iter(seqs.into_iter()))
            .await
    }

    /// Get the list of sequences we haven't yet from the specified batch
    pub async fn get_exclusions(&self, info: &BatchInfo) -> Option<Vec<Sequence>> {
        if let Some(seen) = self.get_seen(*info.digest()).await {
            let range = 0..info.sequence();
            let mut peek = seen.peekable();
            let mut excluded = Vec::new();

            debug!(
                "collection exclusion list for {} of size {}",
                info.digest(),
                info.sequence()
            );

            for i in range {
                let pinned = Pin::new(&mut peek);

                if pinned.next_if_eq(&i).await.is_some() {
                    continue;
                } else {
                    excluded.push(i);
                }
            }

            excluded.into()
        } else {
            None
        }
    }

    /// Get all seen or delivered sequences from the specified batch
    pub async fn get_seen(&self, digest: Digest) -> Option<impl Stream<Item = Sequence>> {
        trace!("getting all seen sequences from batch {}", digest);

        let tx = self.get_agent(digest).await?;

        Self::get_seen_internal(tx, self.capacity).await
    }

    async fn get_seen_internal(
        tx: mpsc::Sender<Command>,
        capacity: usize,
    ) -> Option<impl Stream<Item = Sequence>> {
        let (resp, rx) = mpsc::channel(capacity);

        let _ = tx.send(Command::GetSeen(resp)).await;

        Some(ReceiverStream::new(rx))
    }

    /// Get all seen sequences for every known batch
    #[allow(clippy::needless_collect)]
    pub async fn get_known_batches(
        &self,
    ) -> impl Stream<Item = (Digest, impl Stream<Item = Sequence>)> {
        let agents = self
            .senders
            .read()
            .await
            .iter()
            .map(|(digest, sender)| (*digest, sender.clone()))
            .collect::<Vec<_>>();

        let capacity = self.capacity;

        stream::iter(agents.into_iter()).filter_map(move |(info, sender)| {
            Self::get_seen_internal(sender, capacity).map(move |s| s.map(|s| (info, s)))
        })
    }

    /// Remove all existing tracking information for the specified batch.
    /// All outstanding request for information from this batch will be processed
    /// before the agent is actually stopped
    pub async fn purge(&self, digest: &Digest) {
        self.senders.write().await.remove(digest);
    }

    /// Get the agent channel for some batch without inserting it if it doesn't exist
    async fn get_agent(&self, digest: Digest) -> Option<mpsc::Sender<Command>> {
        self.senders.read().await.get(&digest).map(Clone::clone)
    }

    async fn get_agent_or_insert(&self, digest: Digest) -> mpsc::Sender<Command> {
        self.senders
            .write()
            .await
            .entry(digest)
            .or_insert_with(|| {
                let (tx, rx) = mpsc::channel(self.capacity);

                PendingAgent::new(rx).spawn(digest);

                tx
            })
            .clone()
    }
}

/// A `PendingAgent` handles seen sequence numbers from one batch. It keeps
/// track of which sequence number has been seen (and not delivered) and which ones have
/// already been delivered
struct PendingAgent {
    set: BTreeMap<Sequence, State>,
    receiver: mpsc::Receiver<Command>,
}

impl PendingAgent {
    fn new(receiver: mpsc::Receiver<Command>) -> Self {
        Self {
            set: Default::default(),
            receiver,
        }
    }

    fn spawn(mut self, digest: Digest) -> JoinHandle<Self> {
        task::spawn(
            async move {
                debug!("started agent");

                while let Some(cmd) = self.receiver.recv().await {
                    match cmd {
                        Command::Seen(sequence, resp) => {
                            trace!("checking if {} is already seen", sequence);

                            if let Entry::Vacant(e) = self.set.entry(sequence) {
                                debug!("newly seen sequence {}", sequence);
                                e.insert(State::Seen);
                                let _ = resp.send(sequence);
                            }
                        }
                        Command::Delivered(sequence, resp) => {
                            trace!("checking if {} is already delivered", sequence);

                            if let Entry::Occupied(mut e) = self.set.entry(sequence) {
                                if e.get_mut().set_delivered() {
                                    debug!("newly delivered sequence {}", sequence);

                                    if resp.send(sequence).is_err() {
                                        warn!("did not wait for response to delivery status");
                                    }
                                }
                            }
                        }
                        Command::GetSeen(channel) => {
                            stream::iter(self.set.keys().copied())
                                .zip(stream::repeat(channel))
                                .for_each(|(seq, channel)| async move {
                                    let _ = channel.send(seq).await;
                                })
                                .await;
                        }
                    }
                }

                info!("monitoring agent exiting");

                self
            }
            .instrument(debug_span!("seen_manager", batch = %digest)),
        )
    }
}

#[derive(Debug)]
enum Command {
    Seen(Sequence, Channel),
    Delivered(Sequence, Channel),
    GetSeen(mpsc::Sender<Sequence>),
}

#[cfg(test)]
mod test {
    use super::*;

    use futures::{future, stream};

    use crate::test::generate_batch;

    const SIZE: usize = 10;

    #[tokio::test]
    async fn purging() {
        let batch = generate_batch(SIZE, SIZE);
        let digest = *batch.info().digest();
        let handle = SeenHandle::new(32);

        handle
            .register_seen(digest, stream::iter(0..batch.len()))
            .await
            .enumerate()
            .for_each(|(exp, seq)| async move {
                assert_eq!(exp as Sequence, seq, "incorrect sequence ordering");
            })
            .await;

        handle.purge(&digest).await;

        let result = handle.get_seen(digest).await;

        assert!(result.is_none(), "information was not purged");
    }

    #[tokio::test]
    async fn seen() {
        let batch = generate_batch(SIZE, SIZE);
        let digest = *batch.info().digest();
        let handle = SeenHandle::new(32);
        let seen = stream::iter((0..batch.len()).step_by(2));

        handle
            .register_seen(digest, seen.clone())
            .await
            .enumerate()
            .for_each(|(curr, seq)| async move {
                assert_eq!(curr as Sequence * 2, seq);
            })
            .await;

        handle
            .get_seen(digest)
            .await
            .expect("no data for batch")
            .zip(seen)
            .for_each(|(actual, exp)| async move {
                assert_eq!(actual, exp);
            })
            .await;
    }

    #[tokio::test]
    async fn seen_then_delivered() {
        let batch = generate_batch(SIZE, SIZE);
        let digest = *batch.info().digest();
        let handle = SeenHandle::new(32);
        let range = 0..batch.len();

        handle
            .register_seen(digest, stream::iter(range.clone()))
            .await
            .enumerate()
            .for_each(|(exp, actual)| async move {
                assert_eq!(exp as Sequence, actual);
            })
            .await;

        let new_seen = handle
            .register_seen(digest, stream::once(future::ready(0)))
            .await
            .collect::<Vec<_>>()
            .await;

        assert!(new_seen.is_empty(), "could see sequences twice");

        handle
            .register_delivered(digest, stream::iter(range))
            .await
            .enumerate()
            .for_each(|(exp, actual)| async move {
                assert_eq!(exp as Sequence, actual);
            })
            .await;
    }

    #[tokio::test]
    async fn delivered_then_seen() {
        let batch = generate_batch(SIZE, SIZE);
        let digest = *batch.info().digest();
        let handle = SeenHandle::new(32);
        let range = 0..batch.len();

        let delivered = handle
            .register_delivered(digest, stream::iter(range.clone()))
            .await
            .collect::<Vec<_>>()
            .await;

        assert!(delivered.is_empty(), "could deliver without seeing first");

        handle
            .register_seen(digest, stream::iter(range))
            .await
            .enumerate()
            .for_each(|(exp, actual)| async move {
                assert_eq!(exp as Sequence, actual);
            })
            .await;
    }

    #[tokio::test]
    async fn exclusions() {
        drop::test::init_logger();

        let batch = generate_batch(SIZE, SIZE);
        let digest = *batch.info().digest();
        let handle = SeenHandle::new(32);
        let conflicts = (0..batch.len()).step_by(2).collect::<Vec<_>>();
        let correct = (0..batch.len()).skip(1).step_by(2);

        handle
            .register_seen(digest, stream::iter(correct))
            .await
            .for_each(|_| future::ready(()))
            .await;

        let exclusions = handle.get_exclusions(batch.info()).await.unwrap();

        assert_eq!(exclusions, conflicts);
    }
}

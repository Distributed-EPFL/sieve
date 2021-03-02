use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use drop::async_trait;
use drop::crypto::hash::{hash, Digest, HashError};
use drop::crypto::key::exchange::PublicKey;
use drop::crypto::sign::{self, KeyPair};
use drop::system::manager::Handle;
use drop::system::sender::ConvertSender;
use drop::system::{message, Message, Processor, SampleError, Sampler, Sender, SenderError};

use futures::{stream, Stream, StreamExt};

use murmur::batched::*;

use serde::{Deserialize, Serialize};

use snafu::{OptionExt, ResultExt, Snafu};

use tokio::sync::{mpsc, Mutex, RwLock};

use tracing::{debug, trace};

mod batch;
pub use batch::FilteredBatch;

mod config;
pub use config::BatchedSieveConfig;

mod utils;
use utils::{ConflictHandle, EchoHandle};

/// Type of messages exchanged by the `BatchedSieveAlgorithm`
#[message]
pub enum BatchedSieveMessage<M>
where
    M: Message,
{
    /// Acknowledge a single payload from a given batch
    Ack(Digest, Sequence),
    /// Acknowledge all payloads in a batch with a list of exceptions
    ValidExcept(BatchInfo, Vec<Sequence>),
    #[serde(bound(deserialize = "M: Message"))]
    /// Encapsulated `BatchedMurmur` message
    Murmur(BatchedMurmurMessage<M>),
}

impl<M> From<BatchedMurmurMessage<M>> for BatchedSieveMessage<M>
where
    M: Message,
{
    fn from(msg: BatchedMurmurMessage<M>) -> Self {
        Self::Murmur(msg)
    }
}

/// Type of errors encountered by the `BatchedSieve` algorithm
#[derive(Debug, Snafu)]
pub enum BatchedSieveError {
    #[snafu(display("network error: {}", source))]
    /// Network error during processing
    Network {
        /// Network error cause
        source: SenderError,
    },
    #[snafu(display("channel closed"))]
    /// A channel was closed too early
    Channel,
    #[snafu(display("unable to hash message: {}", source))]
    /// Failure to hash something
    HashFail {
        /// Underlying cause
        source: HashError,
    },
    #[snafu(display("processor was not setup"))]
    /// Processor was not setup correctly before running
    NotSetup,
    #[snafu(display("murmur processing error: {}", source))]
    /// Underlying `BatchedMumur` error
    Murmur {
        /// Underlying cause
        source: BatchProcessingError,
    },
    #[snafu(display("sampling error: {}", source))]
    /// A sample couldn't be obtained using the provided `Sampler`
    Sampling {
        /// Actual error cause
        source: SampleError,
    },
}

impl BatchedSieveError {
    /// Check whether this `BatchedSieve` instance is able to continue after this error
    /// occured<
    pub fn is_fatal(&self) -> bool {
        matches!(self, Self::Channel | Self::NotSetup)
    }
}

type MurmurSender<M, S> = ConvertSender<BatchedMurmurMessage<M>, BatchedSieveMessage<M>, S>;
type MurmurHandle<M, S, R> = BatchedHandle<M, Arc<Batch<M>>, MurmurSender<M, S>, R>;
type SharedHandle<H> = Mutex<Option<H>>;

/// A `Batched` version of the `Sieve` algorithm.
pub struct BatchedSieve<M, S, R>
where
    M: Message + 'static,
    S: Sender<BatchedSieveMessage<M>>,
    R: RdvPolicy,
{
    pending: RwLock<HashMap<Digest, Arc<Batch<M>>>>,
    murmur: Arc<BatchedMurmur<M, R>>,
    handle: SharedHandle<MurmurHandle<M, S, R>>,
    delivered: RwLock<HashMap<Digest, BTreeSet<Sequence>>>,
    delivery: Option<mpsc::Sender<FilteredBatch<M>>>,
    gossip: RwLock<HashSet<PublicKey>>,
    echoes: EchoHandle,
    conflicts: ConflictHandle,
    threshold: usize,
}

impl<M, S, R> BatchedSieve<M, S, R>
where
    M: Message,
    S: Sender<BatchedSieveMessage<M>>,
    R: RdvPolicy,
{
    /// Create a new `BatchedSieve` instance
    ///
    /// # Arguments
    /// - * keypair: local `KeyPair` to use for signing messages
    /// - * threshold: delivery threshold for `Payload`s
    /// - * policy: rendez vous policy to use for batching
    /// - * expected: expected size of local gossip set
    pub fn new(keypair: KeyPair, threshold: usize, policy: R, _expected: usize) -> Self {
        let murmur = Arc::new(BatchedMurmur::new(keypair, policy));

        Self {
            murmur,
            threshold,
            pending: Default::default(),
            delivery: Default::default(),
            delivered: Default::default(),
            handle: Default::default(),
            gossip: Default::default(),
            echoes: EchoHandle::new(32),
            conflicts: ConflictHandle::new(32),
        }
    }

    /// Try registering a possibly new batch and returns a message acknowledging
    async fn register_batch(
        &self,
        batch: Arc<Batch<M>>,
    ) -> Result<Option<BatchedSieveMessage<M>>, BatchedSieveError> {
        use std::collections::hash_map::Entry;

        match self.pending.write().await.entry(*batch.info().digest()) {
            Entry::Occupied(_) => Ok(None),
            Entry::Vacant(e) => {
                let mut i = 0;
                let mut conflicts = Vec::new();
                let batch = e.insert(batch);

                for block in batch.blocks() {
                    for payload in block.iter() {
                        let sender = *payload.sender();
                        let seq = payload.sequence();

                        let digest = hash(&payload).context(HashFail)?;

                        if let Some(true) = self.conflicts.check(sender, seq, digest).await {
                            conflicts.push(i);

                            i += 1;
                        }
                    }
                }

                Ok(Some(BatchedSieveMessage::ValidExcept(
                    *batch.info(),
                    conflicts,
                )))
            }
        }
    }

    /// Process echoes for a set of `Sequence`s
    /// # Returns
    /// A `Stream` containing the `Sequence`s that have reached the threshold of echoes
    async fn process_echo<'a>(
        &'a self,
        info: &BatchInfo,
        from: PublicKey,
        sequences: &'a [Sequence],
    ) -> impl Stream<Item = Sequence> + 'a {
        let acked = (0..info.sequence()).filter(move |x| !sequences.contains(&x));
        let echoes = self.echoes.send_many(*info.digest(), from, acked).await;
        let digest = *info.digest();

        self.echoes
            .many_conflicts(*info.digest(), from, sequences.iter().copied())
            .await;

        echoes.filter_map(move |(seq, x)| async move {
            if x >= self.threshold as i32 {
                debug!(
                    "reached threshold to deliver payload {} of batch {}",
                    seq, digest
                );
                Some(seq)
            } else {
                debug!(
                    "only have {}/{} acks to deliver payload {} of batch {}",
                    x, self.threshold, seq, digest
                );
                None
            }
        })
    }

    /// Check a `Stream`  of sequences to see which ones have already been delivered
    /// # Returns
    /// `Some` if at least one `Sequence` in the `Stream` has not been delivered yet,
    /// `None` otherwise
    async fn deliverable(
        &self,
        digest: Digest,
        sequences: impl Stream<Item = Sequence>,
    ) -> Option<FilteredBatch<M>> {
        let mut delivered = self.delivered.write().await;
        let delivered = delivered.entry(digest).or_default();

        let not_delivered: Vec<Sequence> = sequences
            .filter(|x| {
                let r = !delivered.contains(x);

                async move { r }
            })
            .collect()
            .await;

        if not_delivered.is_empty() {
            trace!("already delivered all acked sequences for  {}", digest);
            None
        } else {
            self.pending
                .read()
                .await
                .get(&digest)
                .map(Clone::clone)
                .map(|batch| {
                    delivered.extend(&not_delivered);
                    FilteredBatch::new(batch, not_delivered)
                })
        }
    }
}

#[async_trait]
impl<M, S, R> Processor<BatchedSieveMessage<M>, M, FilteredBatch<M>, S> for BatchedSieve<M, S, R>
where
    M: Message + 'static,
    R: RdvPolicy,
    S: Sender<BatchedSieveMessage<M>> + 'static,
{
    type Error = BatchedSieveError;

    type Handle = BatchedSieveHandle<M>;

    async fn process(
        self: Arc<Self>,
        message: Arc<BatchedSieveMessage<M>>,
        from: PublicKey,
        sender: Arc<S>,
    ) -> Result<(), Self::Error> {
        match &*message {
            BatchedSieveMessage::ValidExcept(ref info, ref sequences) => {
                debug!(
                    "acknowledged {} payloads from batch {}",
                    info.size() - sequences.len(),
                    info.digest()
                );

                let echoes = self.process_echo(info, from, sequences).await;

                if let Some(batch) = self.deliverable(*info.digest(), echoes).await {
                    debug!(
                        "ready to deliver {} except {} payloads",
                        info,
                        batch.excluded_len()
                    );

                    self.delivery
                        .as_ref()
                        .context(NotSetup)?
                        .send(batch)
                        .await
                        .map_err(|_| snafu::NoneError)
                        .context(Channel)?;
                }
            }
            BatchedSieveMessage::Ack(ref hash, ref sequence) => {
                if let Some((seq, echoes)) = self.echoes.send(*hash, from, *sequence).await {
                    if echoes >= self.threshold as i32 {
                        todo!("deliver payload {} if not already delivered", seq);
                    }
                }
            }
            BatchedSieveMessage::Murmur(murmur) => {
                let msender = Arc::new(ConvertSender::new(sender.clone()));

                self.murmur
                    .clone()
                    .process(Arc::new(murmur.clone()), from, msender)
                    .await
                    .context(Murmur)?;

                let delivery = self
                    .handle
                    .lock()
                    .await
                    .as_mut()
                    .context(NotSetup)?
                    .try_deliver()
                    .await;

                if let Ok(Some(batch)) = delivery {
                    debug!("delivered a new batch via murmur");

                    if let Some(ack) = self.register_batch(batch).await? {
                        sender
                            .send_many(Arc::new(ack), self.gossip.read().await.iter())
                            .await
                            .context(Network)?;
                    }
                }
            }
        }

        Ok(())
    }

    async fn output<SA>(&mut self, sampler: Arc<SA>, sender: Arc<S>) -> Self::Handle
    where
        SA: Sampler,
    {
        let sample = sampler
            .sample(sender.keys().await.iter().copied(), 0)
            .await
            .expect("unable to collect sample");

        self.gossip.write().await.extend(sample);

        let sender = Arc::new(ConvertSender::new(sender));
        let handle = Arc::get_mut(&mut self.murmur)
            .expect("setup should be run first")
            .output(sampler, sender)
            .await;

        self.handle.lock().await.replace(handle);

        let (tx, rx) = mpsc::channel(16);

        self.delivery.replace(tx);

        BatchedSieveHandle::new(rx)
    }
}

/// A `Handle` for interacting with the corresponding `BatchedSieve` instance.
pub struct BatchedSieveHandle<M>
where
    M: Message,
{
    channel: mpsc::Receiver<FilteredBatch<M>>,
}

impl<M> BatchedSieveHandle<M>
where
    M: Message,
{
    /// Create a new `Handle`
    fn new(channel: mpsc::Receiver<FilteredBatch<M>>) -> Self {
        Self { channel }
    }
}

#[async_trait]
impl<M> Handle<M, FilteredBatch<M>> for BatchedSieveHandle<M>
where
    M: Message,
{
    type Error = BatchedSieveError;

    async fn deliver(&mut self) -> Result<FilteredBatch<M>, Self::Error> {
        self.channel.recv().await.ok_or_else(|| Channel.build())
    }

    async fn try_deliver(&mut self) -> Result<Option<FilteredBatch<M>>, Self::Error> {
        use futures::future::{self, Either};
        use std::future::ready;

        match future::select(self.deliver(), ready(None::<()>)).await {
            Either::Left((Ok(payload), _)) => Ok(Some(payload)),
            Either::Left((Err(_), _)) => Channel.fail(),
            Either::Right(_) => Ok(None),
        }
    }

    async fn broadcast(&mut self, message: &M) -> Result<(), Self::Error> {
        todo!("broadcast {:?}", message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIZE: usize = 10;

    use std::iter;

    use drop::test::{keyset, DummyManager};

    use murmur::batched::test::generate_transmit;

    fn message_with_sender<M, I>(
        keys: impl IntoIterator<Item = PublicKey>,
        gen: impl Fn() -> I,
    ) -> impl Iterator<Item = (PublicKey, BatchedSieveMessage<M>)>
    where
        M: Message,
        I: Iterator<Item = BatchedSieveMessage<M>>,
    {
        keys.into_iter().zip(gen())
    }

    #[allow(dead_code)]
    fn generate_valid_except<M: Message>(
        info: BatchInfo,
        count: usize,
        conflicts: impl IntoIterator<Item = Sequence>,
    ) -> impl Iterator<Item = BatchedSieveMessage<M>> {
        let conflicts: Vec<_> = conflicts.into_iter().collect();

        (0..count).map(move |_| BatchedSieveMessage::ValidExcept(info, conflicts.clone()))
    }

    fn generate_no_conflict<M: Message>(
        info: BatchInfo,
        count: usize,
    ) -> impl Iterator<Item = BatchedSieveMessage<M>> {
        generate_valid_except(info, count, iter::empty())
    }

    fn generate_some_conflict<M, I>(
        info: BatchInfo,
        count: usize,
        conflicts: I,
    ) -> impl Iterator<Item = BatchedSieveMessage<M>>
    where
        M: Message,
        I: Iterator<Item = Sequence> + Clone,
    {
        (0..count)
            .zip(iter::repeat(conflicts))
            .map(move |(_, conflicts)| BatchedSieveMessage::ValidExcept(info, conflicts.collect()))
    }

    #[tokio::test]
    async fn deliver_some_conflict() {
        drop::test::init_logger();

        const CONFLICT_RANGE: std::ops::Range<Sequence> =
            (SIZE as Sequence / 2)..(SIZE as Sequence);

        let batch = generate_batch(SIZE);
        let info = *batch.info();
        let keys: Vec<_> = keyset(SIZE).collect();
        let announce = (keys[0], BatchedMurmurMessage::Announce(info, true).into());
        let murmur = iter::once(announce).chain(
            keys.clone()
                .into_iter()
                .zip(generate_transmit(batch.clone()).map(Into::into)),
        );
        let messages = murmur.chain(message_with_sender(keys.clone(), || {
            generate_some_conflict(info, SIZE, CONFLICT_RANGE)
        }));
        let mut manager = DummyManager::with_key(messages, keys);
        let sieve = BatchedSieve::new(KeyPair::random(), SIZE, Fixed::new_local(), 0);

        let mut handle = manager.run(sieve).await;

        let filtered: FilteredBatch<u32> = handle.deliver().await.expect("no delivery");

        assert_eq!(
            filtered.excluded_len(),
            CONFLICT_RANGE.count(),
            "wrong number of conflicts"
        );
        assert_eq!(filtered.len(), SIZE / 2, "wrong number of correct delivery");

        batch
            .into_iter()
            .take(CONFLICT_RANGE.count())
            .zip(filtered.iter())
            .for_each(|(expected, actual)| {
                assert_eq!(&expected, actual, "bad payload");
            });
    }

    #[tokio::test]
    async fn deliver_no_conflict() {
        drop::test::init_logger();

        let batch = generate_batch(SIZE);
        let info = *batch.info();
        let keys: Vec<_> = keyset(SIZE).collect();

        let murmur = keys
            .clone()
            .into_iter()
            .zip(generate_transmit(batch.clone()).map(BatchedSieveMessage::Murmur));
        let sieve = message_with_sender(keys.clone(), || generate_no_conflict(info, SIZE));
        let announce = (keys[0], BatchedMurmurMessage::Announce(info, true).into());
        let messages = iter::once(announce).chain(murmur.chain(sieve));
        let mut manager = DummyManager::with_key(messages, keys.clone());

        let sieve = BatchedSieve::new(KeyPair::random(), SIZE, Fixed::new_local(), 0);

        let mut handle = manager.run(sieve).await;

        let filtered: FilteredBatch<u32> = handle.deliver().await.expect("no delivery");

        assert_eq!(filtered.excluded_len(), 0, "wrong number of conflict");

        batch
            .into_iter()
            .zip(filtered.iter())
            .for_each(|(expected, actual)| {
                assert_eq!(&expected, actual, "bad payload");
            });
    }
}

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

use murmur::*;
pub use murmur::{BatchInfo, Fixed, Payload, RdvPolicy, RoundRobin, Sequence};

use postage::dispatch;
use postage::prelude::{Sink, Stream as _};

use serde::{Deserialize, Serialize};

use snafu::{OptionExt, ResultExt, Snafu};

use tokio::sync::{Mutex, RwLock};

use tracing::{debug, trace, warn};

mod batch;
pub use batch::FilteredBatch;

mod config;
pub use config::{SieveConfig, SieveConfigBuilder};

mod utils;
use utils::ConflictHandle;
pub use utils::EchoHandle;

/// Type of messages exchanged by the `BatchedSieveAlgorithm`
#[message]
pub enum SieveMessage<M>
where
    M: Message,
{
    /// Acknowledge a single payload from a given batch
    Ack(Digest, Sequence),
    /// Acknowledge all payloads in a batch with a list of exceptions
    ValidExcept(BatchInfo, Vec<Sequence>),
    #[serde(bound(deserialize = "M: Message"))]
    /// Encapsulated `BatchedMurmur` message
    Murmur(MurmurMessage<M>),
}

impl<M> From<MurmurMessage<M>> for SieveMessage<M>
where
    M: Message,
{
    fn from(msg: MurmurMessage<M>) -> Self {
        Self::Murmur(msg)
    }
}

impl<M> From<Payload<M>> for SieveMessage<M>
where
    M: Message,
{
    fn from(payload: Payload<M>) -> Self {
        Self::Murmur(payload.into())
    }
}

/// Type of errors encountered by the `BatchedSieve` algorithm
#[derive(Debug, Snafu)]
pub enum SieveError {
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
    MurmurFail {
        /// Underlying cause
        source: MurmurError,
    },
    #[snafu(display("sampling error: {}", source))]
    /// A sample couldn't be obtained using the provided `Sampler`
    Sampling {
        /// Actual error cause
        source: SampleError,
    },
}

impl SieveError {
    /// Check whether this `BatchedSieve` instance is able to continue after this error
    /// occured<
    pub fn is_fatal(&self) -> bool {
        matches!(self, Self::Channel | Self::NotSetup)
    }
}

type MurmurSender<M, S> = ConvertSender<MurmurMessage<M>, SieveMessage<M>, S>;
type MurmurHandleAlias<M, S, R> = MurmurHandle<M, Arc<Batch<M>>, MurmurSender<M, S>, R>;

/// A `Batched` version of the `Sieve` algorithm.
pub struct Sieve<M, S, R>
where
    M: Message + 'static,
    S: Sender<SieveMessage<M>>,
    R: RdvPolicy,
{
    pending: RwLock<HashMap<Digest, Arc<Batch<M>>>>,
    murmur: Arc<Murmur<M, R>>,
    handle: Option<Mutex<MurmurHandleAlias<M, S, R>>>,
    delivered: RwLock<HashMap<Digest, BTreeSet<Sequence>>>,
    delivery: Option<dispatch::Sender<FilteredBatch<M>>>,
    gossip: RwLock<HashSet<PublicKey>>,
    echoes: EchoHandle,
    conflicts: ConflictHandle,
    config: SieveConfig,
}

impl<M, S, R> Sieve<M, S, R>
where
    M: Message,
    S: Sender<SieveMessage<M>>,
    R: RdvPolicy,
{
    /// Create a new `BatchedSieve` instance
    ///
    /// # Arguments
    /// - * keypair: local `KeyPair` to use for signing messages
    /// - * policy: rendez vous policy to use for batching
    /// - * config: BatchedSieveConfig containing all the other options
    pub fn new(keypair: KeyPair, policy: R, config: SieveConfig) -> Self {
        let murmur = Arc::new(Murmur::new(keypair, policy, config.murmur));

        Self {
            murmur,
            config,
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
    ) -> Result<Option<SieveMessage<M>>, SieveError> {
        use std::collections::hash_map::Entry;

        match self.pending.write().await.entry(*batch.info().digest()) {
            Entry::Occupied(_) => Ok(None),
            Entry::Vacant(e) => {
                let mut conflicts = Vec::new();
                let batch = e.insert(batch);

                for (i, block) in batch.blocks().enumerate() {
                    for payload in block.iter() {
                        let sender = *payload.sender();
                        let seq = payload.sequence();

                        let digest = hash(&payload).context(HashFail)?;

                        if let Some(true) = self.conflicts.check(sender, seq, digest).await {
                            warn!(
                                "detected conflict for {:?} in {}",
                                payload.payload(),
                                batch.info().digest()
                            );
                            conflicts.push(i as Sequence);
                        }
                    }
                }

                debug!("total of {} conflicts in {}", conflicts.len(), batch.info());

                Ok(Some(SieveMessage::ValidExcept(*batch.info(), conflicts)))
            }
        }
    }

    /// Process echoes for a set of excluded `Sequence`s
    /// # Returns
    /// A `Stream` containing the `Sequence`s that have reached the threshold of echoes
    async fn process_exceptions<'a>(
        &'a self,
        info: &BatchInfo,
        from: PublicKey,
        sequences: &'a [Sequence],
    ) -> impl Stream<Item = Sequence> + 'a {
        let acked = (0..info.sequence()).filter(move |x| !sequences.contains(&x));
        let echoes = self.echoes.send_many(*info.digest(), from, acked).await;
        let digest = *info.digest();

        let stream = self
            .echoes
            .many_conflicts(*info.digest(), from, sequences.iter().copied())
            .await
            .inspect(|(seq, count)| {
                debug!("{} echoes after conflict signaling for {}", count, seq,)
            });

        futures::pin_mut!(stream);

        stream.into_future().await;

        echoes.filter_map(move |(seq, x)| async move {
            if self.config.threshold_cmp(x) {
                debug!(
                    "reached threshold to deliver payload {} of batch {}",
                    seq, digest
                );
                Some(seq)
            } else {
                debug!(
                    "only have {}/{} acks to deliver payload {} of batch {}",
                    x, self.config.echo_threshold, seq, digest
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

        let not_delivered: BTreeSet<Sequence> = sequences
            .filter(|x| {
                let r = !delivered.contains(x);

                async move { r }
            })
            .collect()
            .await;

        if not_delivered.is_empty() {
            trace!("no new sequences to deliver for {}", digest);
            None
        } else {
            self.pending
                .read()
                .await
                .get(&digest)
                .map(Clone::clone)
                .map(|batch| {
                    delivered.extend(&not_delivered);
                    debug!(
                        "ready to deliver {} new payloads from {}",
                        digest,
                        not_delivered.len(),
                    );

                    FilteredBatch::with_inclusion(batch, &not_delivered)
                })
        }
    }

    async fn deliver(&self, batch: FilteredBatch<M>) -> Result<(), SieveError> {
        debug!(
            "delivering {} payloads from batch {}",
            batch.len(),
            batch.digest()
        );
        self.delivery
            .as_ref()
            .context(NotSetup)?
            .clone()
            .send(batch)
            .await
            .map_err(|_| snafu::NoneError)
            .context(Channel)
    }
}

#[async_trait]
impl<M, S, R> Processor<SieveMessage<M>, Payload<M>, FilteredBatch<M>, S> for Sieve<M, S, R>
where
    M: Message + 'static,
    R: RdvPolicy + 'static,
    S: Sender<SieveMessage<M>> + 'static,
{
    type Error = SieveError;

    type Handle = SieveHandle<M, S, R>;

    async fn process(
        &self,
        message: Arc<SieveMessage<M>>,
        from: PublicKey,
        sender: Arc<S>,
    ) -> Result<(), Self::Error> {
        match &*message {
            SieveMessage::ValidExcept(ref info, ref sequences) => {
                debug!(
                    "acknowledged {} payloads from batch {}",
                    info.size() - sequences.len(),
                    info.digest()
                );

                let echoes = self.process_exceptions(info, from, sequences).await;

                if let Some(batch) = self.deliverable(*info.digest(), echoes).await {
                    self.deliver(batch).await?;
                }
            }
            SieveMessage::Ack(ref digest, ref sequence) => {
                if let Some((seq, echoes)) = self.echoes.send(*digest, from, *sequence).await {
                    debug!("now have {} p-acks for {} of {}", echoes, seq, digest);

                    if self.config.threshold_cmp(echoes) {
                        debug!(
                            "reached threshold for payload {} of batch {}",
                            sequence, digest
                        );

                        if let Some(batch) = self
                            .deliverable(*digest, stream::once(async move { seq }))
                            .await
                        {
                            debug!("ready to deliver payload {} from {}", sequence, digest);

                            self.deliver(batch).await?;
                        }
                    }
                }
            }
            SieveMessage::Murmur(murmur) => {
                let msender = Arc::new(ConvertSender::new(sender.clone()));

                self.murmur
                    .clone()
                    .process(Arc::new(murmur.clone()), from, msender)
                    .await
                    .context(MurmurFail)?;

                let delivery = self
                    .handle
                    .as_ref()
                    .context(NotSetup)?
                    .lock()
                    .await
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
            .sample(
                sender.keys().await.iter().copied(),
                self.config.sieve_sample_size,
            )
            .await
            .expect("unable to collect sample");

        self.gossip.write().await.extend(sample);

        let sender = Arc::new(ConvertSender::new(sender));
        let handle = Arc::get_mut(&mut self.murmur)
            .expect("setup should be run first")
            .output(sampler, sender)
            .await;

        let (disp_tx, disp_rx) = dispatch::channel(self.config.murmur.channel_cap);

        self.handle.replace(Mutex::new(handle.clone()));

        self.delivery.replace(disp_tx);

        SieveHandle::new(handle, disp_rx)
    }
}

impl<M, S> Default for Sieve<M, S, Fixed>
where
    M: Message + 'static,
    S: Sender<SieveMessage<M>>,
{
    fn default() -> Self {
        Self::new(
            KeyPair::random(),
            Fixed::new_local(),
            SieveConfig::default(),
        )
    }
}

/// A `Handle` for interacting with the corresponding `BatchedSieve` instance.
pub struct SieveHandle<M, S, R>
where
    M: Message + 'static,
    S: Sender<SieveMessage<M>>,
    R: RdvPolicy,
{
    handle: MurmurHandle<M, Arc<Batch<M>>, MurmurSender<M, S>, R>,
    dispatch: dispatch::Receiver<FilteredBatch<M>>,
}

impl<M, S, R> SieveHandle<M, S, R>
where
    M: Message + 'static,
    S: Sender<SieveMessage<M>>,
    R: RdvPolicy,
{
    /// Create a new `Handle` using an underlying `Handle` and dispatch receiver for delivery
    fn new(
        handle: MurmurHandle<M, Arc<Batch<M>>, MurmurSender<M, S>, R>,
        dispatch: dispatch::Receiver<FilteredBatch<M>>,
    ) -> Self {
        Self { handle, dispatch }
    }
}

#[async_trait]
impl<M, S, R> Handle<Payload<M>, FilteredBatch<M>> for SieveHandle<M, S, R>
where
    M: Message + 'static,
    S: Sender<SieveMessage<M>>,
    R: RdvPolicy,
{
    type Error = SieveError;

    async fn deliver(&mut self) -> Result<FilteredBatch<M>, Self::Error> {
        self.dispatch.recv().await.ok_or_else(|| Channel.build())
    }

    async fn try_deliver(&mut self) -> Result<Option<FilteredBatch<M>>, Self::Error> {
        use postage::stream::TryRecvError;

        match self.dispatch.try_recv() {
            Ok(message) => Ok(Some(message)),
            Err(TryRecvError::Pending) => Ok(None),
            _ => Channel.fail(),
        }
    }

    async fn broadcast(&mut self, message: &Payload<M>) -> Result<(), Self::Error> {
        self.handle.broadcast(message).await.context(MurmurFail)
    }
}

impl<M, S, R> Clone for SieveHandle<M, S, R>
where
    M: Message + 'static,
    S: Sender<SieveMessage<M>>,
    R: RdvPolicy,
{
    fn clone(&self) -> Self {
        Self {
            handle: self.handle.clone(),
            dispatch: self.dispatch.clone(),
        }
    }
}

#[cfg(any(test, feature = "test"))]
/// Test utilities for [`BatchedSieve`]
///
/// [`BatchedSieve`]: self::BatchedSieve
pub mod test {
    use super::*;

    use std::iter;

    #[cfg(test)]
    use drop::test::DummyManager;

    pub use murmur::test::*;

    /// Generate a sieve acknowledgment for a single payload in a batch
    pub fn generate_single_ack<M>(
        info: BatchInfo,
        count: usize,
        seq: Sequence,
    ) -> impl Iterator<Item = SieveMessage<M>>
    where
        M: Message,
    {
        (0..count).map(move |_| SieveMessage::Ack(*info.digest(), seq))
    }

    /// Generate a sequence of `BatchedSieveMessage` that will result in delivery of
    /// all payloads in the given batch except for the specified conflicts
    pub fn generate_valid_except<M: Message>(
        info: BatchInfo,
        count: usize,
        conflicts: impl IntoIterator<Item = Sequence>,
    ) -> impl Iterator<Item = SieveMessage<M>> {
        let conflicts: Vec<_> = conflicts.into_iter().collect();

        (0..count).map(move |_| SieveMessage::ValidExcept(info, conflicts.clone()))
    }

    ///  Generate a sequence of message with no conflict reports
    pub fn generate_no_conflict<M: Message>(
        info: BatchInfo,
        count: usize,
    ) -> impl Iterator<Item = SieveMessage<M>> {
        generate_valid_except(info, count, iter::empty())
    }

    /// Generate an `Iterator` of conflicts message for the given batch
    pub fn generate_some_conflict<M, I>(
        info: BatchInfo,
        count: usize,
        conflicts: I,
    ) -> impl Iterator<Item = SieveMessage<M>>
    where
        M: Message,
        I: Iterator<Item = Sequence> + Clone,
    {
        (0..count)
            .zip(iter::repeat(conflicts))
            .map(move |(_, conflicts)| SieveMessage::ValidExcept(info, conflicts.collect()))
    }

    /// Generate a complete sequence of messages that will result in delivery of a `Batch` from the
    /// sieve algorithm, excluding the sequences provided in the conflict `Iterator`
    pub fn generate_sieve_sequence<I>(
        peer_count: usize,
        batch: Batch<u32>,
        conflicts: I,
    ) -> impl Iterator<Item = SieveMessage<u32>>
    where
        I: IntoIterator<Item = Sequence>,
        I::IntoIter: Clone,
    {
        let info = *batch.info();
        let murmur = generate_transmit(batch).map(Into::into);
        let sieve = generate_some_conflict(info, peer_count, conflicts.into_iter());

        murmur.chain(sieve)
    }

    #[tokio::test]
    async fn deliver_some_conflict() {
        drop::test::init_logger();

        const SIZE: usize = 10;
        const CONFLICT_RANGE: std::ops::Range<Sequence> =
            (SIZE as Sequence / 2)..(SIZE as Sequence);

        let batch = generate_batch(SIZE);
        let info = *batch.info();
        let announce = MurmurMessage::Announce(info, true).into();
        let murmur = iter::once(announce).chain(generate_transmit(batch.clone()).map(Into::into));
        let messages = murmur.chain(generate_some_conflict(info, SIZE, CONFLICT_RANGE));
        let mut manager = DummyManager::new(messages, SIZE);
        let sieve = Sieve::default();

        let mut handle = manager.run(sieve).await;

        let filtered = handle.deliver().await.expect("no delivery");

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
    async fn reports_conflicts() {
        use drop::crypto::sign::Signer;
        use drop::test::DummyManager;

        const RANGE: std::ops::Range<usize> = 5..8;

        drop::test::init_logger();

        let config = SieveConfig {
            murmur: MurmurConfig {
                sponge_threshold: 1,
                ..Default::default()
            },
            ..Default::default()
        };

        let sieve = Sieve::new(KeyPair::random(), Fixed::new_local(), config);
        let mut signer = Signer::random();
        let sender = *signer.public();
        // send 3 times a different payload with the same sequence number to
        // provoke some conflict
        let payloads = RANGE.map(|x| {
            let signature = signer.sign(&x).expect("signing failed");
            Payload::new(sender, 0, x, signature)
        });

        let batches: Vec<Batch<usize>> = payloads
            .map(|payload| iter::once(iter::once(payload).collect()).collect())
            .collect();

        assert_eq!(batches.len(), RANGE.count());

        let messages = batches.iter().cloned().flat_map(|batch| {
            iter::once(MurmurMessage::Announce(*batch.info(), true))
                .chain(generate_transmit(batch))
                .map(Into::into)
        });

        let mut manager = DummyManager::new(messages, 10);

        manager.run(sieve).await;

        let conflicts = manager
            .sender()
            .messages()
            .await
            .into_iter()
            .map(|x| x.1)
            .fold(HashSet::new(), |mut acc, curr| match &*curr {
                SieveMessage::ValidExcept(info, conflicts) => {
                    acc.extend(iter::repeat(*info.digest()).zip(conflicts.iter().copied()));

                    acc
                }
                _ => acc,
            });

        assert_eq!(
            conflicts.len(),
            RANGE.count() - 1,
            "wrong number of conflicts"
        );
    }

    #[tokio::test]
    async fn deliver_single_payload() {
        drop::test::init_logger();

        const SIZE: usize = 10;
        const CONFLICT_RANGE: std::ops::Range<Sequence> = CONFLICT..(SIZE as Sequence);
        const CONFLICT: Sequence = 5;

        let batch = generate_batch(SIZE);
        let info = *batch.info();

        let announce = iter::once(MurmurMessage::Announce(info, true));
        let murmur = announce
            .chain(generate_transmit(batch.clone()))
            .map(Into::into);
        let messages = murmur
            .chain(generate_some_conflict(info, SIZE, CONFLICT_RANGE))
            .chain(generate_single_ack(info, SIZE, CONFLICT));
        let sieve = Sieve::default();
        let mut manager = DummyManager::new(messages, SIZE);
        let mut handle = manager.run(sieve).await;

        let b1 = handle.deliver().await.expect("failed deliver");
        let b2 = handle.deliver().await.expect("failed deliver");

        assert_eq!(b1.len(), 5);
        assert_eq!(b2.len(), 1);
    }

    #[tokio::test]
    async fn deliver_no_conflict() {
        drop::test::init_logger();

        const SIZE: usize = 10;

        let batch = generate_batch(SIZE);
        let info = *batch.info();

        let murmur = generate_transmit(batch.clone()).map(Into::into);
        let sieve = generate_no_conflict(info, SIZE);
        let announce = MurmurMessage::Announce(info, true).into();
        let messages = iter::once(announce).chain(murmur.chain(sieve));
        let mut manager = DummyManager::new(messages, SIZE);

        let sieve = Sieve::default();

        let mut handle = manager.run(sieve).await;

        let filtered = handle.deliver().await.expect("no delivery");

        assert_eq!(filtered.excluded_len(), 0, "wrong number of conflict");

        batch
            .into_iter()
            .zip(filtered.iter())
            .for_each(|(expected, actual)| {
                assert_eq!(&expected, actual, "bad payload");
            });
    }
}

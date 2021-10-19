use std::collections::{BTreeMap, BTreeSet, HashMap};

use drop::crypto::{key::exchange::PublicKey, Digest};
use futures::stream::{Stream, StreamExt};
use tokio::{
    sync::{mpsc, oneshot},
    task::{self, JoinHandle},
};
use tracing::{error, trace, trace_span};
use tracing_futures::Instrument;

use super::*;
use crate::Sequence;

/// A convenient struct to manage conflicts between `Batch`es. <br />
/// If any of the methods of this returns either `None` or `false` the associated
/// agent has crashed and should be restarted
#[derive(Clone)]
pub struct EchoHandle {
    command: mpsc::Sender<Command>,
}

impl EchoHandle {
    /// Create a new `EchoController` with a channel buffer of `cap`
    pub fn new(cap: usize, name: &str) -> Self {
        let (tx, rx) = mpsc::channel(cap);

        let manager = EchoAgent::new(rx);

        manager.spawn(name);

        Self { command: tx }
    }

    /// Send a `Payload` for conflict validation.
    pub async fn send(&self, batch: Digest, sender: PublicKey, seq: Sequence) -> (Sequence, i32) {
        let (tx, rx) = oneshot::channel();

        if self
            .command
            .send(Command::Received(batch, sender, seq, tx))
            .await
            .is_err()
        {
            error!("echo agent not running");

            (seq, 0)
        } else {
            rx.await.map(|echoes| (seq, echoes)).unwrap_or((seq, 0))
        }
    }

    /// Get echo count for the given sequences
    pub async fn get_echoes(&self, digest: Digest, sequence: Sequence) -> (Sequence, i32) {
        let (tx, rx) = oneshot::channel();

        debug!("getting echo count for {} of {}", sequence, digest);

        trace!("channel buffer available is {}", self.command.capacity());

        if self
            .command
            .send(Command::GetEcho(digest, sequence, tx))
            .await
            .is_err()
        {
            error!("echo agent not running");
            (sequence, 0)
        } else {
            trace!("waiting for answer from agent");

            rx.await
                .map(|count| {
                    debug!("{} from {} has {} echoes", sequence, digest, count);
                    (sequence, count)
                })
                .unwrap_or((sequence, 0))
        }
    }

    /// Get echo statuses for many different sequences in a batch
    pub fn get_many_echoes<'a>(
        &'a self,
        digest: Digest,
        sequences: impl Iterator<Item = Sequence> + 'a,
    ) -> impl Stream<Item = (Sequence, i32)> + 'a {
        debug!("getting many echoes for {}", digest);

        self.get_many_echoes_stream(digest, stream::iter(sequences))
    }

    /// Get the echo count for many sequences from a `Stream`
    pub fn get_many_echoes_stream<'a>(
        &'a self,
        digest: Digest,
        sequences: impl Stream<Item = Sequence> + 'a,
    ) -> impl Stream<Item = (Sequence, i32)> + 'a {
        sequences.then(move |sequence| self.get_echoes(digest, sequence))
    }

    /// Register echoes for many different payloads at once
    pub async fn send_many<'a>(
        &'a self,
        batch: Digest,
        from: PublicKey,
        checks: impl IntoIterator<Item = Sequence> + 'a,
    ) -> impl Stream<Item = (Sequence, i32)> + 'a {
        debug!("registering new echoes from {} for {}", from, batch);

        stream::iter(checks).then(move |seq| self.send(batch, from, seq))
    }

    /// Register a conflicting block from  a given remote peer
    pub async fn conflicts(&self, batch: Digest, peer: PublicKey, sequence: Sequence) {
        self.command
            .send(Command::Conflict(batch, peer, sequence))
            .await
            .ok();
    }

    /// Register many conflicts for different sequences for a single peer
    pub async fn many_conflicts<'a>(
        &'a self,
        batch: Digest,
        peer: PublicKey,
        sequences: impl IntoIterator<Item = Sequence> + 'a,
    ) {
        stream::iter(sequences)
            .then(|seq| self.conflicts(batch, peer, seq))
            .for_each(|_| futures::future::ready(()))
            .await;
    }

    /// Purge all echo information related to the specified Digest
    pub async fn purge(&self, digest: Digest) {
        if let Err(e) = self.command.send(Command::Purge(digest)).await {
            error!("unable to purge agent for {}: {}", digest, e);
        }
    }
}

impl Default for EchoHandle {
    fn default() -> Self {
        Self::new(128, "default")
    }
}

#[derive(Eq, Copy, Clone, Debug)]
/// This implements both PartialEq and Ord manually since we don't want
/// and Okay(x) being replaced in the set by a Conflict(x)
enum EchoStatus {
    Conflict(PublicKey),
    Okay(PublicKey),
}

impl PartialEq for EchoStatus {
    fn eq(&self, other: &Self) -> bool {
        match self {
            Self::Conflict(skey) => match other {
                Self::Conflict(okey) => skey == okey,
                Self::Okay(okey) => skey == okey,
            },
            Self::Okay(skey) => match other {
                Self::Conflict(okey) => skey == okey,
                Self::Okay(okey) => skey == okey,
            },
        }
    }
}

impl Ord for EchoStatus {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match self {
            Self::Conflict(key) => match other {
                Self::Okay(okey) => key.cmp(okey),
                Self::Conflict(okey) => key.cmp(okey),
            },
            Self::Okay(key) => match other {
                Self::Okay(okey) => key.cmp(okey),
                Self::Conflict(okey) => key.cmp(okey),
            },
        }
    }
}

impl PartialOrd for EchoStatus {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug)]
enum Command {
    /// Notify of new `Received` message
    Received(Digest, PublicKey, Sequence, oneshot::Sender<i32>),
    /// The specified payload conflicts for a remote peer
    Conflict(Digest, PublicKey, Sequence),
    /// Purge all echo information
    Purge(Digest),
    /// Get echo count for a given sequence
    GetEcho(Digest, Sequence, oneshot::Sender<i32>),
}

struct EchoAgent {
    receiver: mpsc::Receiver<Command>,
    echoes: HashMap<Digest, EchoList>,
}

impl EchoAgent {
    fn new(receiver: mpsc::Receiver<Command>) -> Self {
        Self {
            receiver,
            echoes: Default::default(),
        }
    }

    fn spawn(self, name: &str) {
        task::spawn(
            self.process_loop()
                .instrument(trace_span!("echo_agent", name=%name)),
        );
    }

    /// Start the processing loop for this `ConflictManager`
    async fn process_loop(mut self) {
        debug!("started echo agent");

        while let Some(command) = self.receiver.recv().await {
            match command {
                Command::Received(hash, sender, sequence, tx) => {
                    let entry = self.echoes.entry(hash).or_default();
                    let conflicts = entry.echo(sequence, sender);

                    trace!("updating echo count for {} of {}", sequence, hash);

                    if tx.send(conflicts).is_err() {
                        warn!("response dropped by requester");
                    }
                }
                Command::Conflict(hash, sender, sequence) => {
                    let entry = self.echoes.entry(hash).or_default();

                    entry.conflicts(sequence, sender);
                }
                Command::Purge(digest) => {
                    self.echoes.remove(&digest);
                }
                Command::GetEcho(digest, sequence, resp) => {
                    trace!("getting echo count for {} of {}", sequence, digest);
                    let echoes = self.echoes.entry(digest).or_default();
                    let count = echoes.count(sequence);

                    trace!("echo count for {} is {}", sequence, count);

                    if resp.send(count).is_err() {
                        error!("channel closed before response was sent");
                    }
                }
            }
        }

        debug!("echo agent exiting");
    }
}

#[derive(Default)]
struct EchoList {
    list: BTreeMap<Sequence, BTreeSet<EchoStatus>>,
}

impl EchoList {
    fn echo(&mut self, sequence: Sequence, pkey: PublicKey) -> i32 {
        let insert = EchoStatus::Okay(pkey);

        self.list
            .entry(sequence)
            .and_modify(|x| {
                x.replace(insert);
            })
            .or_insert_with(|| {
                let mut s = BTreeSet::default();
                s.insert(insert);
                s
            });
        self.count(sequence)
    }

    fn conflicts(&mut self, sequence: Sequence, pkey: PublicKey) -> i32 {
        self.list
            .entry(sequence)
            .and_modify(|x| {
                x.insert(EchoStatus::Conflict(pkey));
            })
            .or_insert_with(|| {
                let mut set = BTreeSet::default();

                set.insert(EchoStatus::Conflict(pkey));

                set
            });

        self.count(sequence)
    }

    fn count(&mut self, sequence: Sequence) -> i32 {
        self.list
            .entry(sequence)
            .or_default()
            .iter()
            .fold(0i32, |acc, curr| {
                if matches!(curr, EchoStatus::Okay(_)) {
                    acc + 1
                } else {
                    acc - 1
                }
            })
    }
}

enum ConflictCommand {
    /// Check if the specified tuple is a conflict
    Check(sign::PublicKey, Sequence, Digest),
}

/// Agent controller that manages conflicts registation
#[derive(Clone)]
pub(super) struct ConflictHandle {
    channel: mpsc::Sender<(ConflictCommand, oneshot::Sender<bool>)>,
}

impl ConflictHandle {
    pub fn new(cap: usize) -> Self {
        let (tx, rx) = mpsc::channel(cap);

        let agent = ConflictAgent::new(rx);

        agent.process_loop();

        Self { channel: tx }
    }

    /// Check if the provided sequence number and sender is a conflict
    pub async fn check(
        &self,
        sender: sign::PublicKey,
        seq: Sequence,
        hash: Digest,
    ) -> Option<bool> {
        self.send_command(ConflictCommand::Check(sender, seq, hash))
            .await
    }

    async fn send_command(&self, cmd: ConflictCommand) -> Option<bool> {
        let (tx, rx) = oneshot::channel();

        if self.channel.send((cmd, tx)).await.is_err() {
            None
        } else {
            rx.await.ok()
        }
    }
}

impl Default for ConflictHandle {
    fn default() -> Self {
        Self::new(128)
    }
}

struct ConflictAgent {
    commands: mpsc::Receiver<(ConflictCommand, oneshot::Sender<bool>)>,
    registered: HashMap<sign::PublicKey, BTreeMap<Sequence, Digest>>,
}

impl ConflictAgent {
    fn new(commands: mpsc::Receiver<(ConflictCommand, oneshot::Sender<bool>)>) -> Self {
        Self {
            commands,
            registered: Default::default(),
        }
    }

    fn process_loop(mut self) -> JoinHandle<Self> {
        task::spawn(async move {
            while let Some((cmd, resp)) = self.commands.recv().await {
                match cmd {
                    ConflictCommand::Check(sender, seq, hash) => {
                        let conflict = self
                            .registered
                            .entry(sender)
                            .or_default()
                            .entry(seq)
                            .or_insert(hash);

                        if resp.send(hash != *conflict).is_err() {
                            error!("agent controller crashed during query");
                            return self;
                        }
                    }
                }
            }

            self
        })
    }
}

#[cfg(test)]
mod test {
    use drop::test::keyset;
    use futures::StreamExt;
    use murmur::test::generate_batch;

    use super::*;

    static SIZE: usize = 100;

    #[tokio::test]
    async fn correct_insert_empty() {
        use drop::crypto::key::exchange::KeyPair;

        drop::test::init_logger();

        let manager = EchoHandle::default();
        let batch = generate_batch(SIZE, SIZE);
        let hash = *batch.info().digest();
        let public = *KeyPair::random().public();

        for seq in 0..batch.len() {
            debug!("inserting payload {} into conflict holder", seq);

            assert_eq!(
                manager.send(hash, public, seq as Sequence).await.1,
                1,
                "wrong ack count"
            );
        }
    }

    #[tokio::test]
    async fn multiple_acks() {
        drop::test::init_logger();

        let manager = EchoHandle::default();
        let batch = generate_batch(1, SIZE);
        let digest = *batch.info().digest();
        let sequence = 0;

        let keys = keyset(SIZE);

        for (count, key) in keys.enumerate() {
            assert_eq!(
                manager.send(digest, key, sequence).await,
                (sequence, count as i32 + 1),
                "incorrect echo number"
            );
        }
    }

    #[tokio::test]
    async fn no_conflict() {
        let manager = ConflictHandle::default();
        let batch = generate_batch(SIZE, SIZE);

        for payload in batch.iter() {
            let digest = hash(payload).expect("hash failed");
            let sequence = payload.sequence();
            let sender = *payload.sender();

            manager
                .check(sender, sequence, digest)
                .await
                .expect("agent failure");
        }
    }

    #[tokio::test]
    async fn many_conflicts() {
        const SEQUENCE: Sequence = 0u32;
        const SIZE: usize = 10;

        use drop::crypto::sign::KeyPair;

        let manager = ConflictHandle::default();
        let sender = KeyPair::random().public();
        let conflicts = (0..SIZE).map(|x| {
            let digest = hash(&x).expect("hash failed");

            (sender, SEQUENCE, digest)
        });

        let mut count = 0;

        for (sender, seq, digest) in conflicts {
            if manager
                .check(sender, seq, digest)
                .await
                .expect("agent failure")
            {
                count += 1;
            }
        }

        assert_eq!(count, SIZE - 1, "wrong number of conflicts");
    }

    #[tokio::test]
    async fn get_echo_count() {
        const SIZE: usize = 10;

        let handle = EchoHandle::default();
        let batch = generate_batch(SIZE, SIZE);
        let digest = *batch.info().digest();
        let keys: Vec<_> = keyset(SIZE).collect();

        let sequences = 0..batch.info().sequence();

        for (idx, key) in keys.into_iter().enumerate() {
            handle
                .send_many(digest, key, sequences.clone())
                .await
                .for_each(|(_, count)| async move {
                    assert_eq!(count, (idx + 1) as i32);
                })
                .await;
        }

        handle
            .get_many_echoes(digest, sequences)
            .for_each(|(_, count)| async move { assert_eq!(count, SIZE as i32) })
            .await;
    }

    #[tokio::test]
    async fn get_many_echoes() {
        const SIZE: usize = 10;

        let handle = EchoHandle::default();
        let batch = generate_batch(SIZE, SIZE);
        let digest = *batch.info().digest();
        let keys = keyset(SIZE);

        let seqs = 0..batch.info().sequence();

        for key in keys {
            handle
                .send_many(digest, key, seqs.clone())
                .await
                .collect::<Vec<_>>()
                .await;
        }

        handle
            .get_many_echoes(digest, seqs)
            .for_each(|(_, count)| async move {
                assert_eq!(count, SIZE as i32);
            })
            .await;
    }

    #[tokio::test]
    async fn pack_retraction() {
        let handle = EchoHandle::default();
        let batch = generate_batch(SIZE, 1);
        let digest = *batch.info().digest();
        let keys: Vec<_> = keyset(SIZE).collect();

        for payload in batch.iter() {
            for key in keys.iter().copied() {
                handle.send(digest, key, payload.sequence()).await;
                handle.conflicts(digest, key, payload.sequence()).await;
            }
        }

        for payload in batch.iter() {
            for key in keys.iter().copied() {
                let (_, echoes) = handle.send(digest, key, payload.sequence()).await;

                assert_eq!(
                    SIZE as i32, echoes,
                    "replaced a positive ack with a conflict"
                );
            }
        }
    }

    #[tokio::test]
    async fn echo_conflict_sum() {
        use futures::future;

        let manager = EchoHandle::default();
        let batch = generate_batch(1, SIZE);

        let echoes = keyset(SIZE / 2);
        let conflicts = keyset(SIZE / 2);
        let digest = *batch.info().digest();

        future::join_all(
            conflicts
                .into_iter()
                .map(|key| manager.conflicts(digest, key, 0)),
        )
        .await;
        let (seq, echo) =
            future::join_all(echoes.into_iter().map(|key| manager.send(digest, key, 0)))
                .await
                .last()
                .map(Clone::clone)
                .unwrap();

        assert_eq!(seq, 0, "wrong sequence number");
        assert_eq!(echo, 0, "wrong echo count");
    }

    #[tokio::test]
    async fn state_switch() {
        let manager = EchoHandle::default();
        let batch = generate_batch(SIZE, SIZE);
        let digest = *batch.info().digest();
        let key = keyset(1).next().unwrap();

        manager
            .many_conflicts(digest, key, 0..batch.info().sequence())
            .await;

        let correct: Vec<_> = (0..batch.info().sequence()).take(SIZE / 2).collect();

        let result = manager.send_many(digest, key, correct.clone()).await;

        futures::pin_mut!(result);

        while let Some((seq, count)) = result.next().await {
            assert!(correct.contains(&seq), "incorrect sequence number");
            assert_eq!(count, 1, "wrong state switch");
        }
    }
}

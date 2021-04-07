use super::*;

use std::collections::{BTreeMap, BTreeSet, HashMap};

use drop::crypto::key::exchange::PublicKey;
use drop::crypto::Digest;

use futures::stream::{FuturesUnordered, Stream, StreamExt};

use murmur::batched::Sequence;

use tokio::sync::{mpsc, oneshot};
use tokio::task::{self, JoinHandle};

use tracing::error;

/// A convenient struct to manage conflicts between `Batch`es. <br />
/// If any of the methods of this returns either `None` or `false` the associated
/// agent has crashed and should be restarted
#[derive(Clone)]
pub struct EchoHandle {
    command: mpsc::Sender<(Command, oneshot::Sender<i32>)>,
}

impl EchoHandle {
    /// Create a new `EchoController` with a channel buffer of `cap`
    pub fn new(cap: usize) -> Self {
        let (tx, rx) = mpsc::channel(cap);

        let manager = EchoAgent::new(rx);
        manager.process_loop();

        Self { command: tx }
    }

    /// Send a `Payload` for conflict validation.
    pub async fn send(
        &self,
        batch: Digest,
        sender: PublicKey,
        seq: Sequence,
    ) -> Option<(Sequence, i32)> {
        if let Some(echoes) = self
            .send_command(Command::Received(batch, sender, seq))
            .await
        {
            Some((seq, echoes))
        } else {
            None
        }
    }

    /// Register echoes for many different payloads at once
    pub async fn send_many<'a>(
        &'a self,
        batch: Digest,
        from: PublicKey,
        checks: impl IntoIterator<Item = Sequence> + 'a,
    ) -> impl Stream<Item = (Sequence, i32)> + 'a {
        checks
            .into_iter()
            .map(|seq| self.send(batch, from, seq))
            .collect::<FuturesUnordered<_>>()
            .filter_map(|x| async move { x })
    }

    /// Register a conflicting block from  a given remote peer
    pub async fn conflicts(
        &self,
        batch: Digest,
        peer: PublicKey,
        sequence: Sequence,
    ) -> Option<(Sequence, i32)> {
        self.send_command(Command::Conflict(batch, peer, sequence))
            .await
            .map(|count| (sequence, count))
    }

    /// Register many conflicts for different sequences for a single peer
    pub async fn many_conflicts<'a>(
        &'a self,
        batch: Digest,
        peer: PublicKey,
        sequences: impl IntoIterator<Item = Sequence> + 'a,
    ) -> impl Stream<Item = (Sequence, i32)> + 'a {
        sequences
            .into_iter()
            .map(|seq| self.conflicts(batch, peer, seq))
            .collect::<FuturesUnordered<_>>()
            .filter_map(|x| async move { x })
    }

    /// Internal helper to send commands to the agent
    async fn send_command(&self, cmd: Command) -> Option<i32> {
        let (tx, rx) = oneshot::channel();

        if self.command.send((cmd, tx)).await.is_err() {
            None
        } else {
            rx.await.ok()
        }
    }
}

impl Default for EchoHandle {
    fn default() -> Self {
        Self::new(128)
    }
}

#[derive(Eq, Copy, Clone, Debug)]
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

enum Command {
    /// Notify of new `Received` message
    Received(Digest, PublicKey, Sequence),
    /// The specified payload conflicts for a remote peer
    Conflict(Digest, PublicKey, Sequence),
}

struct EchoAgent {
    receiver: mpsc::Receiver<(Command, oneshot::Sender<i32>)>,
    echoes: HashMap<Digest, EchoList>,
}

impl EchoAgent {
    fn new(receiver: mpsc::Receiver<(Command, oneshot::Sender<i32>)>) -> Self {
        Self {
            receiver,
            echoes: Default::default(),
        }
    }

    /// Start the processing loop for this `ConflictManager`
    fn process_loop(mut self) -> JoinHandle<Self> {
        task::spawn(async move {
            while let Some((command, tx)) = self.receiver.recv().await {
                match command {
                    Command::Received(hash, sender, sequence) => {
                        let entry = self.echoes.entry(hash).or_default();
                        let conflicts = entry.echo(sequence, sender);

                        if tx.send(conflicts).is_err() {
                            error!("agent controller has died");
                            return self;
                        }
                    }
                    Command::Conflict(hash, sender, sequence) => {
                        let entry = self.echoes.entry(hash).or_default();

                        entry.conflicts(sequence, sender);
                    }
                }
            }

            self
        })
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
    use super::*;

    use drop::test::keyset;

    use futures::StreamExt;

    use murmur::batched::test::generate_batch;

    static SIZE: usize = 100;

    #[tokio::test]
    async fn correct_insert_empty() {
        use drop::crypto::key::exchange::KeyPair;

        drop::test::init_logger();

        let manager = EchoHandle::default();
        let batch = generate_batch(SIZE);
        let hash = *batch.info().digest();
        let public = *KeyPair::random().public();

        for seq in 0..batch.len() {
            debug!("inserting payload {} into conflict holder", seq);

            assert_eq!(
                manager
                    .send(hash, public, seq as Sequence)
                    .await
                    .expect("issue checking conflict")
                    .1,
                1,
                "wrong ack count"
            );
        }
    }

    #[tokio::test]
    async fn multiple_acks() {
        drop::test::init_logger();

        let manager = EchoHandle::default();
        let batch = generate_batch(1);
        let digest = *batch.info().digest();
        let sequence = 0;

        let keys = keyset(SIZE);

        for (count, key) in keys.enumerate() {
            assert_eq!(
                manager.send(digest, key, sequence).await,
                Some((sequence, count as i32 + 1)),
                "incorrect echo number"
            );
        }
    }

    #[tokio::test]
    async fn no_conflict() {
        let manager = ConflictHandle::default();
        let batch = generate_batch(SIZE);

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

        let manager = ConflictHandle::default();
        let sender = *KeyPair::random().public();
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
    async fn pack_retraction() {
        let handle = EchoHandle::default();
        let batch = generate_batch(SIZE / 5);
        let digest = *batch.info().digest();
        let keys: Vec<_> = keyset(SIZE).collect();

        for payload in batch.iter() {
            for key in keys.iter().copied() {
                handle
                    .send(digest, key, payload.sequence())
                    .await
                    .expect("agent failed");
                handle.conflicts(digest, key, payload.sequence()).await;
            }
        }

        for payload in batch.iter() {
            for key in keys.iter().copied() {
                let (_, echoes) = handle
                    .send(digest, key, payload.sequence())
                    .await
                    .expect("oops");

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
        let batch = generate_batch(1);

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
                .flatten()
                .unwrap();

        assert_eq!(seq, 0, "wrong sequence number");
        assert_eq!(echo, 0, "wrong echo count");
    }

    #[tokio::test]
    async fn state_switch() {
        let manager = EchoHandle::default();
        let batch = generate_batch(SIZE);
        let digest = *batch.info().digest();
        let key = keyset(1).next().unwrap();

        manager
            .many_conflicts(digest, key, 0..batch.info().sequence())
            .await
            .collect::<Vec<_>>()
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

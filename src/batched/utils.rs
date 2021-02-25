use super::*;

use std::collections::{BTreeMap, BTreeSet, HashMap};

use drop::crypto::key::exchange::PublicKey;
use drop::crypto::Digest;

use futures::Stream;

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
        stream::iter(checks.into_iter())
            .then(move |seq| self.send(batch, from, seq))
            .filter_map(|x| async move { x })
    }

    /// Register a conflicting block from  a given remote peer
    pub async fn conflicts(&self, batch: Digest, peer: PublicKey, sequence: Sequence) -> bool {
        self.send_command(Command::Conflict(batch, peer, sequence))
            .await
            .is_some()
    }

    /// Register many conflicts for different sequences for a single peer
    pub async fn many_conflicts<'a>(
        &'a self,
        batch: Digest,
        peer: PublicKey,
        sequences: impl IntoIterator<Item = Sequence> + 'a,
    ) -> bool {
        for sequence in sequences.into_iter() {
            if !self.conflicts(batch, peer, sequence).await {
                return false;
            }
        }

        true
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

#[derive(Copy, Clone)]
enum EchoStatus {
    Conflict(PublicKey),
    Okay(PublicKey),
}

impl Eq for EchoStatus {}

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

impl Default for EchoHandle {
    fn default() -> Self {
        Self::new(32)
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
            loop {
                let (command, tx) = match self.receiver.recv().await {
                    Some((command, tx)) => (command, tx),
                    None => return self,
                };

                match command {
                    Command::Received(hash, sender, sequence) => {
                        let conflicts = self.echoes.entry(hash).or_default().echo(sequence, sender);

                        if tx.send(conflicts).is_err() {
                            error!("agent controller has died");
                            return self;
                        }
                    }
                    Command::Conflict(hash, sender, sequence) => {
                        self.echoes
                            .entry(hash)
                            .or_default()
                            .conflicts(sequence, sender);
                    }
                }
            }
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
                x.insert(insert);
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

                        if resp.send(hash == *conflict).is_err() {
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

    use murmur::batched::generate_batch;

    static CAP: usize = 32;
    static SIZE: usize = 100;

    #[tokio::test]
    async fn correct_insert_empty() {
        use drop::crypto::key::exchange::KeyPair;

        drop::test::init_logger();

        let manager = EchoHandle::new(CAP);
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

        let manager = EchoHandle::new(CAP);
        let batch = generate_batch(1);
        let digest = *batch.info().digest();
        let sequence = 0;

        let keys = drop::test::keyset(SIZE);

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
        let manager = ConflictHandle::new(CAP);
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
}

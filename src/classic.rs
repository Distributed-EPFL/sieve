use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::ops::Deref;
use std::sync::Arc;

use drop::crypto::key::exchange::PublicKey;
use drop::crypto::sign::{self, KeyPair, Signature, Signer};
use drop::system::manager::Handle;
use drop::system::sender::ConvertSender;
use drop::system::{message, Message, Processor, Sampler, Sender, SenderError};
use drop::{async_trait, implement_handle};

use murmur::classic::{Murmur, MurmurHandle, MurmurMessage, MurmurProcessingError};

use serde::{Deserialize, Serialize};

use snafu::{IntoError, OptionExt, ResultExt, Snafu};

use tokio::sync::{oneshot, Mutex, RwLock};
use tokio::task;

use tracing::{debug, error, warn};

type SharedHandle<M> = Arc<Mutex<Option<MurmurHandle<(M, Signature)>>>>;

#[message]
/// Type of message exchanged by the `Sieve` algorithm
pub enum SieveMessage<M: Message> {
    #[serde(bound(deserialize = "M: Message"))]
    /// Wraps a message from `Murmur` into a `SieveMessage`
    Probabilistic(MurmurMessage<(M, Signature)>),
    #[serde(bound(deserialize = "M: Message"))]
    /// Message used during echo rounds
    Echo(M, Signature),
    /// Subscribe to the `Echo` set of a remote peer
    EchoSubscribe,
}

impl<M: Message> From<MurmurMessage<(M, Signature)>> for SieveMessage<M> {
    fn from(v: MurmurMessage<(M, Signature)>) -> Self {
        SieveMessage::Probabilistic(v)
    }
}

#[derive(Debug, Snafu)]
/// Error by `Sieve::process` when processing a message
pub enum SieveProcessingError<M: Message> {
    #[snafu(display("network error: {}", source))]
    /// A network error occured
    Network {
        /// Underlying error cause
        source: SenderError,
    },

    #[snafu(display("bad signature from {}", from))]
    /// The processed message had a wrong signature
    BadSignature {
        /// Source of the message with bad signature
        from: PublicKey,
    },

    #[snafu(display("delivery failed"))]
    /// The message contained in this error could not be delivered
    DeliveryFailed {
        /// Undelivered message
        message: M,
    },

    #[snafu(display("murmur error: {}", source))]
    /// Murmur encountered an error processing a message
    MurmurProcess {
        /// Error encountered by `Murmur` during processing
        source: MurmurProcessingError,
    },
}

impl<M: Message> From<DeliveryFailed<M>> for SieveProcessingError<M> {
    fn from(v: DeliveryFailed<M>) -> Self {
        v.into_error(snafu::NoneError)
    }
}

implement_handle!(SieveHandle, SieveError, SieveMessage);

/// An implementation of the `Sieve` probabilistic consistent broadcast
/// algorithm. `Sieve` is a single-shot shot broadcast algorithm using
/// a designated sender for each instance.
pub struct Sieve<M: Message + 'static> {
    deliverer: Mutex<Option<oneshot::Sender<M>>>,
    sender: sign::PublicKey,
    keypair: Arc<KeyPair>,

    expected: usize,

    echo: Mutex<Option<(M, Signature)>>,
    echo_set: RwLock<HashSet<PublicKey>>,
    echo_replies: RwLock<HashMap<PublicKey, (M, Signature)>>,
    echo_threshold: usize,

    murmur: Arc<Murmur<(M, Signature)>>,
    handle: SharedHandle<M>,
}

impl<M: Message> Sieve<M> {
    /// Create a new double echo receiver for the given sender.
    /// * Arguments
    /// `sender` designated sender's public key for this instance
    /// `keypair` local keypair used  for signing
    /// `echo_threshold` number of echo messages to wait for before delivery
    /// `pb_size` expected sample size
    pub fn new_receiver(
        sender: sign::PublicKey,
        keypair: Arc<KeyPair>,
        echo_threshold: usize,
        pb_size: usize,
    ) -> Self {
        let murmur = Murmur::new_receiver(sender, keypair.clone(), pb_size);

        Self {
            sender,
            deliverer: Mutex::new(None),
            keypair,
            expected: pb_size,

            echo: Mutex::new(None),
            echo_threshold,
            echo_set: RwLock::new(HashSet::with_capacity(pb_size)),
            echo_replies: RwLock::new(HashMap::with_capacity(echo_threshold)),

            murmur: Arc::new(murmur),
            handle: Arc::new(Mutex::new(None)),
        }
    }

    /// Create a new `Sieve` receiver.
    pub fn new_sender(keypair: Arc<KeyPair>, echo_threshold: usize, pb_size: usize) -> Self {
        let murmur = Murmur::new_sender(keypair.clone(), pb_size);

        Self {
            sender: *keypair.public(),
            keypair,
            deliverer: Mutex::new(None),
            expected: pb_size,

            echo: Mutex::new(None),
            echo_threshold,
            echo_set: RwLock::new(HashSet::with_capacity(pb_size)),
            echo_replies: RwLock::new(HashMap::with_capacity(echo_threshold)),

            murmur: Arc::new(murmur),
            handle: Arc::new(Mutex::new(None)),
        }
    }

    async fn check_echo_set(&self, signature: &Signature, message: &M) -> bool {
        let count = self
            .echo_replies
            .read()
            .await
            .values()
            .filter(|(stored_message, stored_signature)| {
                stored_message == message && stored_signature == signature
            })
            .count();

        if count >= self.echo_threshold {
            debug!("reached delivery threshold, checking correctness");

            if let Some((recv_msg, recv_signature)) = &*self.echo.lock().await {
                if recv_msg == message && recv_signature == signature {
                    true
                } else {
                    warn!("mismatched message received");
                    false
                }
            } else {
                false
            }
        } else {
            debug!("still waiting for {} messages", self.echo_threshold - count);
            false
        }
    }

    async fn update_echo_set(&self, from: PublicKey, signature: &Signature, message: &M) -> bool {
        if self.echo_set.read().await.contains(&from) {
            match self.echo_replies.write().await.entry(from) {
                Entry::Occupied(_) => false,
                Entry::Vacant(e) => {
                    debug!("registered correct echo message from {}", from);
                    e.insert((message.clone(), *signature));
                    true
                }
            }
        } else {
            false
        }
    }

    fn signer(&self) -> Signer {
        Signer::new(self.keypair.deref().clone())
    }
}

#[async_trait]
impl<M, S> Processor<SieveMessage<M>, M, M, S> for Sieve<M>
where
    S: Sender<SieveMessage<M>> + 'static,
    M: Message + 'static,
{
    type Handle = SieveHandle<M>;

    type Error = SieveProcessingError<M>;

    async fn process(
        self: Arc<Self>,
        message: Arc<SieveMessage<M>>,
        from: PublicKey,
        sender: Arc<S>,
    ) -> Result<(), Self::Error> {
        match message.deref() {
            SieveMessage::Echo(message, signature) => {
                debug!("echo message from {}", from);

                self.signer()
                    .verify(signature, &self.sender, message)
                    .map_err(|_| snafu::NoneError)
                    .context(BadSignature { from })?;

                if self.update_echo_set(from, signature, message).await
                    && self.check_echo_set(signature, message).await
                {
                    if let Some(sender) = self.deliverer.lock().await.take() {
                        return sender
                            .send(message.clone())
                            .map_err(|message| DeliveryFailed { message }.into());
                    } else {
                        debug!("already delivered a message");
                    }
                }

                Ok(())
            }
            SieveMessage::EchoSubscribe => {
                if self.echo_set.write().await.insert(from) {
                    if let Some((message, signature)) = self.echo.lock().await.deref() {
                        debug!("echo subscription from {}", from);
                        let message = SieveMessage::Echo(message.clone(), *signature);

                        sender
                            .send(Arc::new(message), &from)
                            .await
                            .context(Network)?;
                    }
                }

                Ok(())
            }

            SieveMessage::Probabilistic(msg) => {
                debug!("processing murmur message {:?}", msg);

                let murmur_sender = Arc::new(ConvertSender::new(sender.clone()));

                self.murmur
                    .clone()
                    .process(Arc::new(msg.clone()), from, murmur_sender)
                    .await
                    .context(MurmurProcess)?;

                let mut guard = self.handle.lock().await;

                if let Some(mut handle) = guard.take() {
                    if let Ok(Some((message, signature))) = handle.try_deliver().await {
                        debug!("delivered {:?} using murmur", message);
                        *self.echo.lock().await = Some((message, signature));
                    } else {
                        guard.replace(handle);
                    }
                } else {
                    debug!("late message for probabilistic broadcast");
                }

                Ok(())
            }
        }
    }

    async fn output<SA: Sampler>(&mut self, sampler: Arc<SA>, sender: Arc<S>) -> Self::Handle {
        let (outgoing_tx, outgoing_rx) = oneshot::channel();
        let (incoming_tx, incoming_rx) = oneshot::channel();
        let subscribe_sender = sender.clone();

        let sample = sampler
            .sample(sender.keys().await.iter().copied(), self.expected)
            .await
            .expect("sampling failed");

        let murmur_sender = Arc::new(ConvertSender::new(sender));
        let handle = Arc::get_mut(&mut self.murmur)
            .expect("setup error")
            .output(sampler.clone(), murmur_sender)
            .await;

        debug!("sampling for echo set");

        self.echo_set.write().await.extend(sample);

        if let Err(e) = subscribe_sender
            .send_many(
                Arc::new(SieveMessage::EchoSubscribe),
                self.echo_set.read().await.iter(),
            )
            .await
        {
            error!("could not send subscriptions: {}", e);
        }

        self.handle.lock().await.replace(handle);
        self.deliverer.lock().await.replace(incoming_tx);

        let outgoing_tx = if self.sender == *self.keypair.public() {
            let handle = self.handle.clone();

            task::spawn(async move {
                if let Ok(msg) = outgoing_rx.await {
                    if let Some(handle) = handle.lock().await.as_mut() {
                        if let Err(e) = handle.broadcast(&msg).await {
                            error!("unable to broadcast message using murmur: {}", e);
                        }
                    }
                } else {
                    error!("broadcast sender not used");
                }
            });

            Some(outgoing_tx)
        } else {
            None
        };

        SieveHandle::new(self.keypair.clone(), incoming_rx, outgoing_tx)
    }
}

#[cfg(any(feature = "test", test))]
/// Public test utilities
pub mod test {
    use super::*;

    use drop::test::*;
    use murmur::classic::test::murmur_message_sequence;

    #[cfg(test)]
    const SIZE: usize = 50;
    #[cfg(test)]
    const MESSAGE: usize = 0;

    /// Generate a test case for delivery of $message using a test network of
    /// $count peers
    #[cfg(test)]
    macro_rules! sieve_test {
        ($message:expr, $count:expr) => {
            init_logger();

            let keypair = Arc::new(KeyPair::random());
            let message = $message;
            let sender = Arc::new(KeyPair::random());
            let (mut manager, signature) = create_sieve_manager(&sender, message.clone(), $count);

            let processor =
                Sieve::new_receiver(sender.public().clone(), keypair.clone(), SIZE / 5, SIZE / 3);

            let mut handle = manager.run(processor).await;

            let received = handle.deliver().await.expect("deliver failed");

            let mut signer = Signer::new(keypair.deref().clone());

            assert_eq!(message, received, "wrong message delivered");
            assert!(
                signer
                    .verify(&signature, sender.public(), &received)
                    .is_ok(),
                "bad signature"
            );
        };
    }

    /// Create a `DummyManager` that will deliver the correct sequence of
    /// messages required for delivery of one sieve message
    pub fn create_sieve_manager<T: Message + Clone + 'static>(
        keypair: &KeyPair,
        message: T,
        peer_count: usize,
    ) -> (DummyManager<SieveMessage<T>, T>, Signature) {
        let mut signer = Signer::new(keypair.clone());
        let signature = signer.sign(&message).expect("sign failed");
        let echos = sieve_message_sequence(keypair, message, peer_count).collect::<Vec<_>>();
        let keys = keyset(peer_count).collect::<Vec<_>>();
        let messages = keys
            .iter()
            .chain(keys.iter())
            .cloned()
            .zip(echos)
            .collect::<Vec<_>>();

        (DummyManager::with_key(messages, keys), signature)
    }

    /// Create a correct sequence of sieve messages
    pub fn sieve_message_sequence<M: Message + 'static>(
        keypair: &KeyPair,
        message: M,
        peer_count: usize,
    ) -> impl Iterator<Item = SieveMessage<M>> {
        let signature = Signer::new(keypair.clone())
            .sign(&message)
            .expect("sign failed");

        let gossip = murmur_message_sequence((message.clone(), signature), keypair, peer_count)
            .map(SieveMessage::Probabilistic);

        gossip.chain((0..peer_count).map(move |_| SieveMessage::Echo(message.clone(), signature)))
    }

    #[test]
    fn sequence_generation() {
        let keypair = KeyPair::random();
        let message = 0usize;
        let count = 25;
        let messages = sieve_message_sequence(&keypair, message, count);

        assert_eq!(messages.count(), count * 2);
    }

    #[tokio::test]
    async fn deliver_vec_no_network() {
        let msg = vec![0u64, 1, 2, 3, 4, 5, 6, 7];

        sieve_test!(msg, SIZE);
    }

    #[tokio::test]
    async fn delivery_usize_no_network() {
        sieve_test!(0, SIZE);
    }

    #[tokio::test]
    async fn delivery_enum_no_network() {
        #[message]
        enum T {
            Ok,
            Error,
            Other,
        }

        let msg = T::Error;

        sieve_test!(msg, SIZE);
    }

    #[tokio::test]
    async fn broadcast_no_network() {
        init_logger();

        let keypair = Arc::new(KeyPair::random());
        let (mut manager, signature) = create_sieve_manager(&keypair, MESSAGE, SIZE);

        let processor = Sieve::new_sender(keypair.clone(), SIZE / 5, SIZE / 3);

        let mut handle = manager.run(processor).await;

        handle.broadcast(&MESSAGE).await.expect("broadcast failed");

        let message = handle.deliver().await.expect("deliver failed");

        Signer::random()
            .verify(&signature, keypair.public(), &MESSAGE)
            .expect("bad signature");
        assert_eq!(message, MESSAGE, "wrong message delivered");
    }
}

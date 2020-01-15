#![cfg_attr(not(feature = "std"), no_std)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Error {
	InvalidSignature,
	InvalidPublicKey,
	InvalidSecretKey,
	InvalidRecoveryId,
	InvalidMessage,
	InvalidInputLength,
	TweakOutOfRange,
}

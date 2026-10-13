{- |
Module: DoubleRatchet.Class
Copyright: (c) 2026 Arjun Khandkar
License: MIT
Maintainer: khandkararjun@gmail.com
Stability: experimental

The 'DoubleRatchet' class, which needs to be instantiated to use the state machine provided by this package.
-}
module DoubleRatchet.Class
  ( DoubleRatchet (..)
  )
where

class DoubleRatchet impl where
  -- | Root key that produces chain keys
  type RootKey impl

  -- | Chain key that produces encryption keys
  type SendingChainKey impl

  -- | Chain key that produces decryption keys
  type ReceivingChainKey impl

  -- | Encryption/decryption key type
  type SymmetricKey impl

  -- | DH secret key
  type SecretKey impl

  -- | DH public key
  type PublicKey impl

  -- | DH shared secret
  type SharedSecret impl

  type OurId impl

  type TheirId impl

  -- | How large the skipped message map can grow
  maximumSkippedMessageMapSize :: Int

  -- | Derive the public key for a secret key
  toPublicKey :: SecretKey impl -> PublicKey impl

  -- | DH shared secret derivation
  deriveSharedSecret :: PublicKey impl -> SecretKey impl -> SharedSecret impl

  -- | Primitive to ratchet sending chain key
  deriveNextSendingChainKey :: SendingChainKey impl -> (SymmetricKey impl, SendingChainKey impl)

  -- | Primitive to ratchet receiving chain key
  deriveNextReceivingChainKey :: ReceivingChainKey impl -> (SymmetricKey impl, ReceivingChainKey impl)

  -- | Initialize the root key
  initializeRootRatchet
    :: OurId impl
    -> TheirId impl
    -> SharedSecret impl
    -- ^ DH secret from initial key exchange
    -> (RootKey impl, SendingChainKey impl, ReceivingChainKey impl)
    -- ^ Initial root key along with sending chain key and receiving chain key

  -- | Primitive to ratchet root key to get sending chain key
  deriveNextRootSending
    :: RootKey impl
    -- ^ Existing root key
    -> OurId impl
    -> TheirId impl
    -> SharedSecret impl
    -- ^ Fresh DH secret
    -> (RootKey impl, SendingChainKey impl)
    -- ^ New root ratchet key along with sending chain key

  -- | Primitive to ratchet root key to get receiving chain key
  deriveNextRootReceiving
    :: RootKey impl
    -- ^ Existing root key
    -> OurId impl
    -> TheirId impl
    -> SharedSecret impl
    -- ^ Fresh DH secret
    -> (RootKey impl, ReceivingChainKey impl)
    -- ^ New root ratchet key along with receiving chain key

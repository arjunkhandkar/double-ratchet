{- |
Module: DoubleRatchet.Class
Copyright: (c) 2026 Arjun Khandkar
License: MIT
Maintainer: khandkararjun@gmail.com
Stability: experimental

This module exposes the 'DoubleRatchet' class, which needs to be instantiated to use the
state machine provided by this package.
-}
module DoubleRatchet.Class
  ( DoubleRatchet (..)
  )
where

{- | This class accepts pure primitives. This is by design; the state machine provided by this package
is deterministic.
-}
class DoubleRatchet impl where
  -- | Key for the root ratchet that spawns chain ratchets
  type RootKey impl

  {- | Key for the sending chain ratchet. This can resolve to the same type as 'ReceivingChainKey',
  but a separate type family has been provided to help avoid ambiguity.
  -}
  type SendingChainKey impl

  {- | Key for the receiving chain ratchet. This can resolve to the same type as 'SendingChainKey',
  but a separate type family has been provided to help avoid ambiguity.
  -}
  type ReceivingChainKey impl

  {- | A key produced by a chain ratchet, which can be used as symmetric key material to encrypt
  and decrypt messages
  -}
  type MessageKey impl

  -- | Secret key that can be fed into a DH algorithm
  type SecretKey impl

  -- | Public key that can be fed into a DH algorithm
  type PublicKey impl

  -- | DH-derived shared secret
  type SharedSecret impl

  {- | Our identity. This can resolve to the same type as 'TheirId', but a separate type family
  has been provided to help avoid ambiguity.
  -}
  type OurId impl

  {- | Thier identity. This can resolve to the same type as 'OurId', but a separate type family
  has been provided to help avoid ambiguity.
  -}
  type TheirId impl

  -- | Derive the public key for a secret key
  toPublicKey :: SecretKey impl -> PublicKey impl

  -- | Derive a shared secret from a public key and a secret key
  deriveSharedSecret :: PublicKey impl -> SecretKey impl -> SharedSecret impl

  {- | Derive the next sending chain key from the current and get a new message key.
  Depending on your instance, this can be the same as 'deriveNextReceivingChainKey'.
  -}
  deriveNextSendingChainKey :: SendingChainKey impl -> (MessageKey impl, SendingChainKey impl)

  {- | Derive the next receiving chain key from the current and get a new message key.
  Depending on your instance, this can be the same as 'deriveNextSendingChainKey'.
  -}
  deriveNextReceivingChainKey :: ReceivingChainKey impl -> (MessageKey impl, ReceivingChainKey impl)

  -- | Initialize the root key and get sending and receiving chain keys
  initializeRootRatchet
    :: OurId impl
    -> TheirId impl
    -> SharedSecret impl
    -- ^ DH secret from initial key exchange
    -> (RootKey impl, SendingChainKey impl, ReceivingChainKey impl)
    -- ^ Initial root key along with sending chain key and receiving chain key

  -- | Derive the next root key from the current and get a new chain key for a sending chain ratchet
  deriveNextRootKeySending
    :: RootKey impl
    -- ^ Existing root ratchet key
    -> OurId impl
    -> TheirId impl
    -> SharedSecret impl
    -- ^ Fresh DH secret
    -> (RootKey impl, SendingChainKey impl)
    -- ^ New root ratchet key along with sending chain key

  -- | Derive the next root key from the current and get a new chain key for a receiving chain ratchet
  deriveNextRootKeyReceiving
    :: RootKey impl
    -- ^ Existing root ratchet key
    -> OurId impl
    -> TheirId impl
    -> SharedSecret impl
    -- ^ Fresh DH secret
    -> (RootKey impl, ReceivingChainKey impl)
    -- ^ New root ratchet key along with receiving chain key

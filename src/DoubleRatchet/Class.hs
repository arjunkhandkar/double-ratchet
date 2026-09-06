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
  -- | Root key that ratchets to produce chain keys
  type RootKey impl

  {- | Chain key that ratchets to produce symmetric keys to encrypt messages.
  This can resolve to the same type as 'ReceivingChain', but a separate type family
  has been provided to help avoid ambiguity.
  -}
  type SendingChainKey impl

  {- | Chain that ratchets to produce symmetric keys to decrypt messages.
  This can resolve to the same type as 'SendingChain', but a separate type family
  has been provided to help avoid ambiguity.
  -}
  type ReceivingChainKey impl

  -- | A key produced by after a chain key ratchet, which can be used to encrypt and decrypt messages
  type SymmetricKey impl

  -- | Secret key for DH exchange
  type SecretKey impl

  -- | Public key for DH exchange
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

  {- | Derive the next sending chain key from the current and get a new symmetric key.
  Depending on your instance, this can be the same as 'deriveNextReceivingChainKey'.
  -}
  deriveNextSendingChainKey :: SendingChainKey impl -> (SymmetricKey impl, SendingChainKey impl)

  {- | Derive the next receiving chain key from the current and get a new symmetric key.
  Depending on your instance, this can be the same as 'deriveNextSendingChainKey'.
  -}
  deriveNextReceivingChainKey :: ReceivingChainKey impl -> (SymmetricKey impl, ReceivingChainKey impl)

  -- | Initialize the root key and get sending and receiving chain keys
  initializeRootRatchet
    :: OurId impl
    -> TheirId impl
    -> SharedSecret impl
    -- ^ DH secret from initial key exchange
    -> (RootKey impl, SendingChainKey impl, ReceivingChainKey impl)
    -- ^ Initial root key along with sending chain key and receiving chain key

  -- | Derive the next root key from the current and get a new chain key to generate encryption keys
  deriveNextRootSending
    :: RootKey impl
    -- ^ Existing root key
    -> OurId impl
    -> TheirId impl
    -> SharedSecret impl
    -- ^ Fresh DH secret
    -> (RootKey impl, SendingChainKey impl)
    -- ^ New root ratchet key along with sending chain key

  -- | Derive the next root key from the current and get a new chain key to generate decryption keys
  deriveNextRootReceiving
    :: RootKey impl
    -- ^ Existing root key
    -> OurId impl
    -> TheirId impl
    -> SharedSecret impl
    -- ^ Fresh DH secret
    -> (RootKey impl, ReceivingChainKey impl)
    -- ^ New root ratchet key along with receiving chain key

{-# LANGUAGE ImportQualifiedPost #-}

module Test.Implementation
  ( TestImplementation
  )
where

import DoubleRatchet.Class (DoubleRatchet (..))
import Test.ToyCrypto qualified as ToyCrypto

data TestImplementation

instance DoubleRatchet TestImplementation where
  type RootKey TestImplementation = ToyCrypto.Root
  type SendingChainKey TestImplementation = ToyCrypto.SendingChain
  type ReceivingChainKey TestImplementation = ToyCrypto.ReceivingChain
  type SymmetricKey TestImplementation = ToyCrypto.SymmetricKey
  type SecretKey TestImplementation = ToyCrypto.SecretKey
  type PublicKey TestImplementation = ToyCrypto.PublicKey
  type SharedSecret TestImplementation = ToyCrypto.SharedSecret
  type OurId TestImplementation = ToyCrypto.OurUserId
  type TheirId TestImplementation = ToyCrypto.TheirUserId
  toPublicKey = ToyCrypto.toPublic
  deriveSharedSecret = ToyCrypto.dh
  deriveNextSendingChainKey = ToyCrypto.deriveNextSendingChain
  deriveNextReceivingChainKey = ToyCrypto.deriveNextReceivingChain
  initializeRootRatchet = ToyCrypto.initializeRoot
  deriveNextRootSending = ToyCrypto.deriveNextRootSending
  deriveNextRootReceiving = ToyCrypto.deriveNextRootReceiving

{-# LANGUAGE ImportQualifiedPost #-}

module Test.Implementation
  ( TestImplementation
  )
where

import DoubleRatchet.Class (DoubleRatchet (..))
import Test.ToyCrypto qualified as ToyCrypto

data TestImplementation

instance DoubleRatchet TestImplementation where
  type Root TestImplementation = ToyCrypto.Root
  type SendingChain TestImplementation = ToyCrypto.SendingChain
  type ReceivingChain TestImplementation = ToyCrypto.ReceivingChain
  type SymmetricKey TestImplementation = ToyCrypto.SymmetricKey
  type SecretKey TestImplementation = ToyCrypto.SecretKey
  type PublicKey TestImplementation = ToyCrypto.PublicKey
  type SharedSecret TestImplementation = ToyCrypto.SharedSecret
  type OurId TestImplementation = ToyCrypto.OurUserId
  type TheirId TestImplementation = ToyCrypto.TheirUserId
  toPublicKey = ToyCrypto.toPublic
  deriveSharedSecret = ToyCrypto.dh
  deriveNextSendingChain = ToyCrypto.deriveNextSendingChain
  deriveNextReceivingChain = ToyCrypto.deriveNextReceivingChain
  initializeRootRatchet = ToyCrypto.initializeRoot
  deriveNextRootSending = ToyCrypto.deriveNextRootSending
  deriveNextRootReceiving = ToyCrypto.deriveNextRootReceiving

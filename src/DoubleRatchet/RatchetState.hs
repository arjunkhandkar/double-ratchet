{- |
Module: DoubleRatchet.RatchetM
Copyright: (c) 2026 Arjun Khandkar
License: MIT
Maintainer: khandkararjun@gmail.com
Stability: experimental

State types for the double ratchet state machine
-}
module DoubleRatchet.RatchetState
  ( -- ** Root ratchet state
    RatchetState

    -- ** Chain ratchet states
  , ReceivingChainState
  , SendingChainState

    -- ** Create a RatchetState
  , initializeRatchetState

    -- ** Inspecting RatchetState
  , dhSecretKey
  , root
  , sendingChainState
  , receivingChainState

    -- ** Inspecting ReceivingChainState
  , nextSendingMessageIndex
  , previousSendingChainLength
  , sendingChainKey

    -- ** Inspecting SendingChainState
  , knownReceivingChainEpochs
  , nextReceivingMessageIndex
  , receivingChainKey
  , receivingChainEpoch
  , skippedMessageMap
  )
where

import Data.Map.Strict qualified as Map
import Data.Set qualified as Set
import DoubleRatchet.Class (DoubleRatchet (..))

data SendingChainState impl = SendingChainState
  { sendingChainKey :: SendingChainKey impl
  -- ^ Chain key from which message key and subsequent chain keys issue
  , nextSendingMessageIndex :: Int
  -- ^ Sending chain length after the next chain ratchet advance
  , previousSendingChainLength :: Int
  -- ^ Chain length of the previous sending chain ratchet
  }

data ReceivingChainState impl = ReceivingChainState
  { receivingChainKey :: ReceivingChainKey impl
  -- ^ Chain key from which message key and subsequent chain keys issue
  , receivingChainEpoch :: PublicKey impl
  -- ^ Sender's public key, used to synchronize state
  , knownReceivingChainEpochs :: Set.Set (PublicKey impl)
  -- ^ Set of known sender public keys
  , nextReceivingMessageIndex :: Int
  -- ^ Receiving chain length after the next chain ratchet advance
  , skippedMessageMap :: Map.Map (PublicKey impl, Int) (MessageKey impl)
  -- ^ Message keys that the state machine has advanced past without consuming
  }

data RatchetState impl = RatchetState
  { root :: RootKey impl
  -- ^ Key for the root ratchet
  , dhSecretKey :: SecretKey impl
  -- ^ Our secret key
  , sendingChainState :: SendingChainState impl
  -- ^ Sending chain ratchet state
  , receivingChainState :: ReceivingChainState impl
  -- ^ Receiving chain ratchet state
  }

initializeRatchetState
  :: forall impl
   . DoubleRatchet impl
  => PublicKey impl
  -- ^ Their public key
  -> SecretKey impl
  -- ^ Our secret key
  -> OurId impl
  -- ^ Our identity
  -> TheirId impl
  -- ^ Their identity
  -> RatchetState impl
initializeRatchetState dhPublicKey' dhSecretKey' ourUserId theirUserId =
  let derivedSecret = deriveSharedSecret @impl dhPublicKey' dhSecretKey'
      (rootKey', sendingChainKey', receivingChainKey') =
        initializeRootRatchet @impl ourUserId theirUserId derivedSecret
   in RatchetState
        { root = rootKey'
        , dhSecretKey = dhSecretKey'
        , sendingChainState =
            SendingChainState
              { sendingChainKey = sendingChainKey'
              , nextSendingMessageIndex = 0
              , previousSendingChainLength = 0
              }
        , receivingChainState =
            ReceivingChainState
              { receivingChainEpoch = dhPublicKey'
              , knownReceivingChainEpochs = Set.singleton dhPublicKey'
              , receivingChainKey = receivingChainKey'
              , nextReceivingMessageIndex = 0
              , skippedMessageMap = Map.empty
              }
        }

{- |
Module: DoubleRatchet.RatchetM
Copyright: (c) 2026 Arjun Khandkar
License: MIT
Maintainer: khandkararjun@gmail.com
Stability: experimental

Transformations over 'RatchetState'
-}
module DoubleRatchet.RatchetM
  ( -- ** Run computations against RatchetState
    RatchetM
  , runRatchetM

    -- ** RatchetState manipulation
  , advanceReceivingChain
  , advanceSendingChain
  , advanceSendingRatchet

    -- ** Helper types
  , SymmetricKeyId (..)
  )
where

import Control.Monad.State (State, gets, modify, runState)
import Data.List (unsnoc)
import Data.Map.Strict qualified as Map
import Data.Set qualified as Set
import DoubleRatchet.Class (DoubleRatchet (..))
import DoubleRatchet.RatchetState

-- | A computation over a 'RatchetState'
type RatchetM impl = State (RatchetState impl)

-- | Run a computation against a 'RatchetState'
runRatchetM
  :: forall impl a
   . RatchetState impl
  -- ^ Initial ratchet state
  -> RatchetM impl a
  -- ^ Computation to run
  -> (a, RatchetState impl)
  -- ^ The result of the computation along with the new ratchet state
runRatchetM = flip runState

{- | Advance the receiving chain ratchet and derive a key that can be used to decrypt a message.
This function may automatically advance the root ratchet to derive a fresh receiving chain,
if necessary. It will return 'Nothing' if the message key identified by the supplied message
key ID was previously returned by the ratchet.
-}
advanceReceivingChain
  :: forall impl
   . (DoubleRatchet impl, Ord (PublicKey impl))
  => SymmetricKeyId (PublicKey impl)
  -> OurId impl
  -> TheirId impl
  -> RatchetM impl (Maybe (SymmetricKey impl))
advanceReceivingChain messageKeyId ourUserId theirUserId = do
  currentReceivingChainEpoch <- gets (receivingChainEpoch . receivingChainState)
  knownReceivingChainEpochs' <- gets (knownReceivingChainEpochs . receivingChainState)

  -- Requesting a key in the same chain epoch as our receiving chain state
  if chainEpoch messageKeyId == currentReceivingChainEpoch then
    currentEpochLookup
  -- Requesting a key in an older chain epoch
  else
    if chainEpoch messageKeyId `Set.member` knownReceivingChainEpochs' then do
      -- Since it's an older epoch, we go straight to the skipped message cache
      skippedMessageMap' <- gets (skippedMessageMap . receivingChainState)
      let messageKeyMaybe =
            Map.lookup (chainEpoch messageKeyId, keyIndex messageKeyId) skippedMessageMap'

      -- Delete the message from the skipped message cache
      modify $ \s ->
        s
          { receivingChainState =
              (receivingChainState s)
                { skippedMessageMap =
                    Map.delete (chainEpoch messageKeyId, keyIndex messageKeyId) (skippedMessageMap $ receivingChainState s)
                }
          }

      -- If we can't find a message key, it must have already been consumed... or we got a bogus message key ID
      -- Either way, we don't care
      pure messageKeyMaybe

    -- Requesting a key in a new epoch
    else do
      -- Update the set of known epochs
      modify $ \s ->
        s
          { receivingChainState =
              (receivingChainState s)
                { knownReceivingChainEpochs =
                    Set.insert (chainEpoch messageKeyId) (knownReceivingChainEpochs $ receivingChainState s)
                }
          }

      -- Advance ratchet and get a new sending chain key
      advanceReceivingRatchet (chainEpoch messageKeyId) (previousChainLength messageKeyId) ourUserId theirUserId

      -- Now that we are in the correct epoch, we can do a current-epoch lookup
      currentEpochLookup
 where
  currentEpochLookup :: RatchetM impl (Maybe (SymmetricKey impl))
  currentEpochLookup = do
    nextReceivingIndex <- gets (nextReceivingMessageIndex . receivingChainState)
    if (keyIndex messageKeyId) == nextReceivingIndex then
      fmap Just singleAdvanceReceivingChain
    else
      if (keyIndex messageKeyId) > nextReceivingIndex then do
        chainKey <- gets (receivingChainKey . receivingChainState)
        oldMissedMessageMap <- gets (skippedMessageMap . receivingChainState)
        latestReceivingChainEpoch <- gets (receivingChainEpoch . receivingChainState)
        let (skippedSymmetricKeys, newChainKey) =
              advanceReceivingFromTo @impl
                nextReceivingIndex
                (keyIndex messageKeyId)
                chainKey
        let newSkippedMessageMapEntries =
              Map.fromList $
                fmap
                  (\(missedSymmetricKey, index) -> ((latestReceivingChainEpoch, index), missedSymmetricKey))
                  skippedSymmetricKeys
            newSkippedMessageMap = Map.union oldMissedMessageMap newSkippedMessageMapEntries
        modify $ \s ->
          s
            { receivingChainState =
                (receivingChainState s)
                  { skippedMessageMap = newSkippedMessageMap
                  , receivingChainKey = newChainKey
                  , nextReceivingMessageIndex = keyIndex messageKeyId
                  }
            }
        fmap Just singleAdvanceReceivingChain
      else do
        latestReceivingChainEpoch <- gets (receivingChainEpoch . receivingChainState)
        skippedMessageMap' <- gets (skippedMessageMap . receivingChainState)
        let messageKeyMaybe =
              Map.lookup (latestReceivingChainEpoch, (keyIndex messageKeyId)) skippedMessageMap'
        modify $ \s ->
          s
            { receivingChainState =
                (receivingChainState s)
                  { skippedMessageMap =
                      Map.delete (latestReceivingChainEpoch, keyIndex messageKeyId) (skippedMessageMap $ receivingChainState s)
                  }
            }
        pure messageKeyMaybe

singleAdvanceReceivingChain
  :: forall impl
   . DoubleRatchet impl
  => RatchetM impl (SymmetricKey impl)
singleAdvanceReceivingChain = do
  chainKey <- gets (receivingChainKey . receivingChainState)
  let (messageKey, nextChainKey) = deriveNextReceivingChain @impl chainKey
  modify $ \s ->
    s
      { receivingChainState =
          (receivingChainState s)
            { receivingChainKey = nextChainKey
            , nextReceivingMessageIndex = nextReceivingMessageIndex (receivingChainState s) + 1
            }
      }
  pure messageKey

advanceReceivingRatchet
  :: forall impl
   . (DoubleRatchet impl, Ord (PublicKey impl))
  => PublicKey impl
  -- ^ DH public key
  -> Int
  -- ^ Previous chain length
  -> OurId impl
  -> TheirId impl
  -> RatchetM impl ()
advanceReceivingRatchet dhPubKey previousChainLength ourUserId theirUserId = do
  -- Cache any skipped message keys if we're behind the sender
  chainIndex <- gets (nextReceivingMessageIndex . receivingChainState)
  chainKey <- gets (receivingChainKey . receivingChainState)
  oldMissedMessageMap <- gets (skippedMessageMap . receivingChainState)
  oldReceivingChainEpoch <- gets (receivingChainEpoch . receivingChainState)
  -- We discard the chain key as we'll get a new one from the advanced root
  let (skippedSymmetricKeys, _) = advanceReceivingFromTo @impl chainIndex previousChainLength chainKey
  let newSkippedMessageMapEntries =
        Map.fromList $
          fmap
            (\(missedSymmetricKey, index) -> ((oldReceivingChainEpoch, index), missedSymmetricKey))
            skippedSymmetricKeys
      newSkippedMessageMap = Map.union oldMissedMessageMap newSkippedMessageMapEntries
  oldRoot <- gets root
  dhSecretKey' <- gets dhSecretKey
  let newDhSecret = deriveSharedSecret @impl dhPubKey dhSecretKey'
      (newRoot, newReceivingChain) =
        deriveNextRootReceiving
          @impl
          oldRoot
          ourUserId
          theirUserId
          newDhSecret
  modify $ \s ->
    s
      { root = newRoot
      , receivingChainState =
          (receivingChainState s)
            { skippedMessageMap = newSkippedMessageMap
            , nextReceivingMessageIndex = 0
            , receivingChainEpoch = dhPubKey
            , receivingChainKey = newReceivingChain
            }
      }

advanceReceivingFromTo
  :: forall impl
   . DoubleRatchet impl
  => Int
  -> Int
  -> ReceivingChain impl
  -> ([(SymmetricKey impl, Int)], ReceivingChain impl)
advanceReceivingFromTo from to chainKey = do
  let go _ 0 = []
      go ck num =
        let (mk, nCk) = deriveNextReceivingChain @impl ck
         in (mk, nCk) : (go nCk (num - 1))
  if from < to then
    let newKeys = go chainKey (to - from)
     in case (fmap snd $ unsnoc newKeys) of
          Nothing -> ([], chainKey)
          Just (_, finalChainKey) -> (zip (fmap fst newKeys) [from ..], finalChainKey)
  else
    ([], chainKey) -- we're caught up or are already ahead

{- | Advance the sending chain ratchet and derive a key that can be used to encrypt a message.
Also returns a message key ID and the length of the previous sending chain, both of which are
needed for state synchronization with the other participant.
-}
advanceSendingChain
  :: forall impl
   . DoubleRatchet impl
  => RatchetM impl (SymmetricKeyId (PublicKey impl), SymmetricKey impl)
  -- ^ Message key ID, message key and previous sending chain length
advanceSendingChain = do
  -- Fetch current sending chain key and index
  currentChainKey <- gets (sendingChainKey . sendingChainState)
  keyIndex <- gets (nextSendingMessageIndex . sendingChainState)
  -- Derive message key and next sending chain key
  let (messageKey, nextChainKey) = deriveNextSendingChain @impl currentChainKey
  -- Update sending chain key and next sending message index
  modify $ \s ->
    s
      { sendingChainState =
          (sendingChainState s)
            { sendingChainKey = nextChainKey
            , nextSendingMessageIndex = keyIndex + 1
            }
      }
  -- Get current sending chain epoch and previous chain length
  chainEpoch <- fmap (toPublicKey @impl) $ gets dhSecretKey
  previousChainLength <- gets (previousSendingChainLength . sendingChainState)
  pure (SymmetricKeyId {..}, messageKey)

advanceSendingRatchet
  :: forall impl
   . DoubleRatchet impl
  => SecretKey impl
  -- ^ *Our* new secret key
  -> OurId impl
  -> TheirId impl
  -> RatchetM impl ()
advanceSendingRatchet newSecretKey ourUserId theirUserId = do
  oldRoot <- gets root
  previousSendingChainLength' <- gets (nextSendingMessageIndex . sendingChainState)
  dhPublicKey' <- gets (receivingChainEpoch . receivingChainState)
  let newDhSecret = deriveSharedSecret @impl dhPublicKey' newSecretKey
      (newRoot, newSendingChain) =
        deriveNextRootSending
          @impl
          oldRoot
          ourUserId
          theirUserId
          newDhSecret
  modify $ \s ->
    s
      { root = newRoot
      , dhSecretKey = newSecretKey
      , sendingChainState =
          (sendingChainState s)
            { nextSendingMessageIndex = 0
            , sendingChainKey = newSendingChain
            , previousSendingChainLength = previousSendingChainLength'
            }
      }

-- | Uniquely identify a message key
data SymmetricKeyId dhPublicKey = SymmetricKeyId
  { keyIndex :: Int
  , chainEpoch :: dhPublicKey
  , previousChainLength :: Int
  }
  deriving (Eq, Ord, Show)

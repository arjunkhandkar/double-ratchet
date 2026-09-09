{- |
Module: DoubleRatchet.RatchetM
Copyright: (c) 2026 Arjun Khandkar
License: MIT
Maintainer: khandkararjun@gmail.com
Stability: experimental

Transformations over 'RatchetState'
-}
module DoubleRatchet.RatchetM
  ( -- * Run computations against RatchetState
    RatchetM
  , runRatchetM

    -- ** Results of computations
  , RatchetFailure (..)

    -- * RatchetState manipulation
  , ratchetReceivingChainKey
  , ratchetSendingChainKey
  , advanceRootKey

    -- * Identifying symmetric keys
  , SymmetricKeyId (..)
  )
where

import Control.Monad (unless)
import Control.Monad.Except (Except, MonadError (throwError), runExcept)
import Control.Monad.State (StateT (runStateT), gets, modify)
import Data.List (unsnoc)
import Data.Map.Strict qualified as Map
import Data.Set qualified as Set
import DoubleRatchet.Class (DoubleRatchet (..))
import DoubleRatchet.State
  ( RatchetState (..)
  , RatchetStateError
  , ReceivingChainState (..)
  , SendingChainState (..)
  , validateRatchetState
  )

-- | A computation over a 'RatchetState'
type RatchetM impl = StateT (RatchetState impl) (Except RatchetFailure)

-- | Run a computation against a 'RatchetState'
runRatchetM
  :: forall impl a
   . RatchetState impl
  -- ^ Initial ratchet state
  -> RatchetM impl a
  -- ^ Computation to run
  -> Either RatchetFailure (a, RatchetState impl)
  -- ^ If successful, the result of the computation along with the new ratchet state.
runRatchetM s a = runExcept $ runStateT a s

-- | The ways a computation over ratchet state could fail.
data RatchetFailure
  = {- | The ratchet state is invalid. Any computations against an invalid ratchet
    state will fail and result in no mutation of state.
    -}
    InvalidRatchetState [RatchetStateError]
  | {- | The maximum chain length for a sending (or receiving) chain has been reached and thus
    the chain key cannot be ratcheted. The root key must be ratcheted before re-attempting to
    ratchet the chain key.

    Under normal circumstances, this should not be returned while attempting to advance the
    receiving chain key as a well-behaved sender will rachet their root key before they
    exceed the maximum chain length on their sending chain key, which will trigger an automatic
    root key ratchet on the receiving side.
    -}
    MaxChainLengthReached
  deriving (Eq, Show)

{- | Ratchet the receiving chain key and generate a symmetric key that can be used to decrypt a message.
If necessary, this function may automatically ratchet the root key to derive a fresh receiving chain key.
-}
ratchetReceivingChainKey
  :: forall impl
   . (DoubleRatchet impl, Ord (PublicKey impl))
  => SymmetricKeyId (PublicKey impl)
  {- ^ Uniquely identify the symmetric key to generate. This would be the output of 'ratchetSendingChainKey'
  sent over the wire along with an encrypted message.
  -}
  -> OurId impl
  -> TheirId impl
  -> RatchetM impl (Maybe (SymmetricKey impl))
  {- ^ May be Nothing if the symmetric key identified by SymmetricKeyId was previously returned by
  the ratchet; the ratchet cannot produce any symmetric key more than once.
  -}
ratchetReceivingChainKey messageKeyId ourUserId theirUserId = do
  assertValidRatchetState

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

    -- The requested key index matches our next receiving index
    if keyIndex messageKeyId == nextReceivingIndex then
      singleAdvanceReceivingChain
    else
      -- The requested key index is beyond our next receiving index but within the maximum chain length
      if (keyIndex messageKeyId > nextReceivingIndex)
        && (keyIndex messageKeyId <= maximumChainLength @impl)
      then do
        chainKey <- gets (receivingChainKey . receivingChainState)
        oldMissedMessageMap <- gets (skippedMessageMap . receivingChainState)
        latestReceivingChainEpoch <- gets (receivingChainEpoch . receivingChainState)
        let (skippedSymmetricKeys, newChainKey) =
              advanceReceivingFromTo @impl nextReceivingIndex (keyIndex messageKeyId) chainKey
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
        singleAdvanceReceivingChain

      -- We have ratcheted past the requested key index, check the skipped key cache
      else
        if keyIndex messageKeyId < nextReceivingIndex then do
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
        -- We have been requested a key index beyond maximum chain length; do nothing
        else
          pure Nothing

singleAdvanceReceivingChain
  :: forall impl
   . (DoubleRatchet impl, Ord (PublicKey impl))
  => RatchetM impl (Maybe (SymmetricKey impl))
singleAdvanceReceivingChain = do
  assertValidRatchetState
  chainKey <- gets (receivingChainKey . receivingChainState)
  nextIndex <- gets (nextReceivingMessageIndex . receivingChainState)
  -- Advance only if we haven't reached the maximum chain length
  if nextIndex < maximumChainLength @impl then do
    let (messageKey, nextChainKey) = deriveNextReceivingChainKey @impl chainKey
    modify $ \s ->
      s
        { receivingChainState =
            (receivingChainState s)
              { receivingChainKey = nextChainKey
              , nextReceivingMessageIndex = nextIndex + 1
              }
        }
    pure $ Just messageKey
  else
    pure Nothing

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
  assertValidRatchetState
  -- Cache any skipped message keys if we're behind the sender
  chainIndex <- gets (nextReceivingMessageIndex . receivingChainState)
  chainKey <- gets (receivingChainKey . receivingChainState)
  oldMissedMessageMap <- gets (skippedMessageMap . receivingChainState)
  oldReceivingChainEpoch <- gets (receivingChainEpoch . receivingChainState)
  let skippedSymmetricKeys =
        fst $
          advanceReceivingFromTo @impl
            chainIndex
            (min previousChainLength (maximumChainLength @impl)) -- Previous chain shouldn't grow beyond max chain length
            chainKey
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
  -> ReceivingChainKey impl
  -> ([(SymmetricKey impl, Int)], ReceivingChainKey impl)
advanceReceivingFromTo from to chainKey = do
  let go _ 0 = []
      go ck num =
        let (mk, nCk) = deriveNextReceivingChainKey @impl ck
         in (mk, nCk) : (go nCk (num - 1))
  if from < to then
    let newKeys = go chainKey (to - from)
     in case (fmap snd $ unsnoc newKeys) of
          Nothing -> ([], chainKey)
          Just (_, finalChainKey) -> (zip (fmap fst newKeys) [from ..], finalChainKey)
  else
    ([], chainKey) -- we're caught up or are already ahead

{- | Ratchet the sending chain key and generate a symmetric key that can be used to encrypt a message.
Returns information identifying the symmetric key that can be transferred over the wire and used
to generate the same key on the receiving end.

Fails with 'MaxChainLengthReached' if the maximum chain length has been reached, i.e. if the sending
chain key has been 'maximumChainLength' times.
-}
ratchetSendingChainKey
  :: forall impl
   . (DoubleRatchet impl, Ord (PublicKey impl))
  => RatchetM impl (SymmetricKeyId (PublicKey impl), SymmetricKey impl)
  -- ^ Message key ID, message key and previous sending chain length
ratchetSendingChainKey = do
  assertValidRatchetState
  -- Fetch current sending chain key and index
  currentChainKey <- gets (sendingChainKey . sendingChainState)
  keyIndex <- gets (nextSendingMessageIndex . sendingChainState)
  if keyIndex < maximumChainLength @impl then do
    -- Derive message key and next sending chain key
    let (messageKey, nextChainKey) = deriveNextSendingChainKey @impl currentChainKey
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
    pure $ (SymmetricKeyId {..}, messageKey)
  else
    throwError MaxChainLengthReached -- Maximum chain length has been reached

{- | Ratchet the root key. Invoked after generating a fresh DH secret, this also generates a
fresh sending chain key and resets related fields ('nextSendingMessageIndex', 'previousSendingChainLength').
-}
advanceRootKey
  :: forall impl
   . (DoubleRatchet impl, Ord (PublicKey impl))
  => SecretKey impl
  -- ^ Our new secret key
  -> OurId impl
  -> TheirId impl
  -> RatchetM impl ()
advanceRootKey newSecretKey ourUserId theirUserId = do
  assertValidRatchetState
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

-- | Uniquely identify a symmetric key.
data SymmetricKeyId dhPublicKey = SymmetricKeyId
  { keyIndex :: Int
  {- ^ The sequence number for the symmetric key within the current chain epoch.
  Analogous to how many time its producing chain key has ratcheted.
  -}
  , chainEpoch :: dhPublicKey
  {- ^ Public key that the chain key is associated with. Changes whenever
  fresh entropy is introduced to the state machine via DH key exhange.
  -}
  , previousChainLength :: Int
  {- ^ The count of keys generated by the chain key from the previous chain epoch.
  This is uniquely determined by 'chainEpoch'.
  -}
  }
  deriving (Eq, Show)

-- | Canonical ordering for 'SymmetricKey'. Within chain epochs, ties are broken by key index.
instance Ord dhPublicKey => Ord (SymmetricKeyId dhPublicKey) where
  compare ski1 ski2 =
    case compare (chainEpoch ski1) (chainEpoch ski2) of
      EQ -> compare (keyIndex ski1) (keyIndex ski2)
      defOrdering -> defOrdering

-- | Assert that the ratchet state is valid. Quit early if not.
assertValidRatchetState :: forall impl. (DoubleRatchet impl, Ord (PublicKey impl)) => RatchetM impl ()
assertValidRatchetState =
  gets validateRatchetState >>= \rsErrors ->
    unless (rsErrors == []) $ throwError $ InvalidRatchetState rsErrors

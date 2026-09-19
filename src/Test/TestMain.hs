{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE ViewPatterns #-}

module Test.TestMain
  ( testMain
  )
where

import Control.Monad (forM, replicateM)
import Data.List (sort)
import DoubleRatchet.RatchetM
  ( ratchetReceivingChainKey
  , ratchetSendingChainKey
  , runRatchetM
  )
import DoubleRatchet.State (initializeRatchetState)
import DoubleRatchet.State qualified as RatchetState
import Hedgehog.Gen (sample, shuffle)
import Test.HUnit.Base (assertFailure)
import Test.Hspec (describe, hspec, it, shouldBe)
import Test.Implementation (TestImplementation)
import Test.ToyCrypto qualified as ToyCrypto

testMain :: IO ()
testMain = hspec $ do
  describe "Post-initialization, before the first root ratchet..." $ do
    it "Both parties derive the same initial root key" sameInitialRoot
    it "Both parties derive the same sending and corresponding receiving keys in order" firstEpochInOrder
    it "Both parties derive the same sending and corresponding receiving keys out of order" firstEpochOutOfOrder
  describe "After a root ratchet..." $ do
    it "Both parties derive the same root key" samePostRatchetRoot
    it "Both parties derive the same sending and corresponding receiving keys in order" secondEpochInOrder
    it "Both parties derive the same sending and corresponding receiving keys out of order" secondEpochOutOfOrder
  describe "Across chain epochs..." $ do
    it "Receiving keys can be requested for previous epochs" crossEpochReceivingKeys
  describe "Disallowed behavior..." $ do
    it "Cannot generate the same key more than once" duplicateKeyRequest
    it "Imposes a limit on the size of the skipped message key map" skippedMessageKeyMapSizeLimit

sameInitialRoot :: IO ()
sameInitialRoot = do
  -- Generate keys
  (aliceSec0, alicePub0) <- ToyCrypto.genKeyPair
  (bobSec0, bobPub0) <- ToyCrypto.genKeyPair
  -- Initialize double ratchets
  let aliceR0 = initializeRatchetState @TestImplementation bobPub0 aliceSec0 aliceAlicePov bobAlicePov
      bobR0 = initializeRatchetState @TestImplementation alicePub0 bobSec0 bobBobPov aliceBobPov
  -- Both parties have derived the same root key
  RatchetState.root aliceR0 `shouldBe` RatchetState.root bobR0

firstEpochInOrder :: IO ()
firstEpochInOrder = do
  -- Generate keys
  (aliceSec0, alicePub0) <- ToyCrypto.genKeyPair
  (bobSec0, bobPub0) <- ToyCrypto.genKeyPair
  -- Initialize double ratchets
  let aliceR0 = initializeRatchetState @TestImplementation bobPub0 aliceSec0 aliceAlicePov bobAlicePov
      bobR0 = initializeRatchetState @TestImplementation alicePub0 bobSec0 bobBobPov aliceBobPov
  -- Alice generates 5 sending keys
  (aliceKeys, _) <-
    expectRight $ runRatchetM @TestImplementation aliceR0 $ replicateM 5 $ ratchetSendingChainKey
  -- Bob generates 5 receiving keys
  (bobKeys, _) <-
    expectRight $
      runRatchetM @TestImplementation bobR0 $
        forM aliceKeys $ \(key, _) ->
          fmap (key,) $ ratchetReceivingChainKey key bobBobPov aliceBobPov
  -- Keys should match
  bobKeys `shouldBe` aliceKeys

firstEpochOutOfOrder :: IO ()
firstEpochOutOfOrder = do
  -- Generate keys
  (aliceSec0, alicePub0) <- ToyCrypto.genKeyPair
  (bobSec0, bobPub0) <- ToyCrypto.genKeyPair
  -- Initialize double ratchets
  let aliceR0 = initializeRatchetState @TestImplementation bobPub0 aliceSec0 aliceAlicePov bobAlicePov
      bobR0 = initializeRatchetState @TestImplementation alicePub0 bobSec0 bobBobPov aliceBobPov
  -- Alice generates 5 sending keys
  (aliceKeys, _) <-
    expectRight $ runRatchetM @TestImplementation aliceR0 $ replicateM 5 $ ratchetSendingChainKey
  -- Shuffle Alice's keys, and by extension, the order in which Bob derives receiving keys
  shuffledAliceKeys <- sample $ shuffle aliceKeys
  -- Bob generates 5 receiving keys
  (bobKeys, _) <-
    expectRight $
      runRatchetM @TestImplementation bobR0 $
        forM shuffledAliceKeys $ \(key, _) ->
          fmap (key,) $ ratchetReceivingChainKey key bobBobPov aliceBobPov
  -- Keys should match
  sort bobKeys `shouldBe` aliceKeys

samePostRatchetRoot :: IO ()
samePostRatchetRoot = pure ()

secondEpochInOrder :: IO ()
secondEpochInOrder = pure ()

secondEpochOutOfOrder :: IO ()
secondEpochOutOfOrder = pure ()

crossEpochReceivingKeys :: IO ()
crossEpochReceivingKeys = pure ()

duplicateKeyRequest :: IO ()
duplicateKeyRequest = pure ()

skippedMessageKeyMapSizeLimit :: IO ()
skippedMessageKeyMapSizeLimit = pure ()

aliceAlicePov, bobBobPov :: ToyCrypto.OurUserId
(aliceAlicePov, bobBobPov) = (ToyCrypto.OurUserId "alice", ToyCrypto.OurUserId "bob")

bobAlicePov, aliceBobPov :: ToyCrypto.TheirUserId
(bobAlicePov, aliceBobPov) = (ToyCrypto.TheirUserId "bob", ToyCrypto.TheirUserId "alice")

expectRight :: Show l => Either l r -> IO r
expectRight = \case
  Left l -> assertFailure $ "Expected Right, but got Left: " <> show l
  Right r -> pure r

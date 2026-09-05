{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Test.TestMain
  ( testMain
  )
where

import Control.Monad (forM, replicateM)
import Data.List (sort)
import Data.Maybe (catMaybes)
import DoubleRatchet.RatchetM (advanceReceivingChain, advanceSendingChain, runRatchetM)
import DoubleRatchet.RatchetState (initializeRatchetState)
import DoubleRatchet.RatchetState qualified as RatchetState
import Hedgehog.Gen (sample, shuffle)
import Test.Hspec (describe, hspec, it, shouldBe)
import Test.Implementation (TestImplementation)
import Test.ToyCrypto qualified as ToyCrypto

testMain :: IO ()
testMain = hspec $
  describe "Post-initialization, before the first root ratchet..." $ do
    it "Both parties derive the same initial root key" sameInitialRoot
    it "Both parties derive the same sending and corresponding receiving keys in order" firstEpochInOrder
    it "Both parties derive the same sending and corresponding receiving keys out of order" firstEpochOutOfOrder

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
  let (aliceKeys, _) =
        runRatchetM @TestImplementation aliceR0 $ replicateM 5 $ advanceSendingChain
  -- Bob generates 5 receiving keys
  let (bobKeys, _) =
        runRatchetM @TestImplementation bobR0 $
          forM aliceKeys $ \(key, _) ->
            fmap (key,) $ advanceReceivingChain key bobBobPov aliceBobPov
  -- Keys should match
  filterNotFound bobKeys `shouldBe` aliceKeys

firstEpochOutOfOrder :: IO ()
firstEpochOutOfOrder = do
  -- Generate keys
  (aliceSec0, alicePub0) <- ToyCrypto.genKeyPair
  (bobSec0, bobPub0) <- ToyCrypto.genKeyPair
  -- Initialize double ratchets
  let aliceR0 = initializeRatchetState @TestImplementation bobPub0 aliceSec0 aliceAlicePov bobAlicePov
      bobR0 = initializeRatchetState @TestImplementation alicePub0 bobSec0 bobBobPov aliceBobPov
  -- Alice generates 5 sending keys
  let (aliceKeys, _) =
        runRatchetM @TestImplementation aliceR0 $ replicateM 5 $ advanceSendingChain
  -- Shuffle Alice's keys, and by extension, the order in which Bob derives receiving keys
  shuffledAliceKeys <- sample $ shuffle aliceKeys
  -- Bob generates 5 receiving keys
  let (bobKeys, _) =
        runRatchetM @TestImplementation bobR0 $
          forM shuffledAliceKeys $ \(key, _) ->
            fmap (key,) $ advanceReceivingChain key bobBobPov aliceBobPov
  -- Keys should match
  sort (filterNotFound bobKeys) `shouldBe` aliceKeys

aliceAlicePov, bobBobPov :: ToyCrypto.OurUserId
(aliceAlicePov, bobBobPov) = (ToyCrypto.OurUserId "alice", ToyCrypto.OurUserId "bob")

bobAlicePov, aliceBobPov :: ToyCrypto.TheirUserId
(bobAlicePov, aliceBobPov) = (ToyCrypto.TheirUserId "bob", ToyCrypto.TheirUserId "alice")

filterNotFound :: [(a, Maybe b)] -> [(a, b)]
filterNotFound = catMaybes . fmap (\(a, b) -> case b of Nothing -> Nothing; Just b' -> Just (a, b'))

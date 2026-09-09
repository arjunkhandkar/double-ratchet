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
import Data.Maybe (catMaybes)
import DoubleRatchet.RatchetM
  ( RatchetFailure (MaxChainLengthReached)
  , SymmetricKeyId (SymmetricKeyId)
  , advanceRootKey
  , ratchetReceivingChainKey
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
    it "Receiving chain key cannot be ratcheted arbitrarily" arbitrarySkips
  describe "When the maximum chain length is reached..." $ do
    it "Symmetric keys cannot be generated unless root key is ratcheted" maxChainLengthReached
    it "Symmetric keys can be generated after a root key ratchet" postMaxChainLengthReached

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
  sort (filterNotFound bobKeys) `shouldBe` aliceKeys

arbitrarySkips :: IO ()
arbitrarySkips = do
  -- Generate keys
  (aliceSec0, _) <- ToyCrypto.genKeyPair
  (_, bobPub0) <- ToyCrypto.genKeyPair
  -- Initialize double ratchets
  let aliceR0 = initializeRatchetState @TestImplementation bobPub0 aliceSec0 aliceAlicePov bobAlicePov
  -- A symmetric key ID that requires an arbitrarily large number of chain key
  -- ratchets beyond what 'maximumChainLength' permits
  let unreasonableKeyId = SymmetricKeyId 9 bobPub0 0
  (aliceKey, _) <-
    expectRight $
      runRatchetM @TestImplementation aliceR0 $
        ratchetReceivingChainKey unreasonableKeyId aliceAlicePov bobAlicePov
  -- Key shouldn't be generated
  aliceKey `shouldBe` Nothing

maxChainLengthReached :: IO ()
maxChainLengthReached = do
  -- Generate keys
  (aliceSec0, _) <- ToyCrypto.genKeyPair
  (_, bobPub0) <- ToyCrypto.genKeyPair
  -- Initialize double ratchet
  let aliceR0 = initializeRatchetState @TestImplementation bobPub0 aliceSec0 aliceAlicePov bobAlicePov
  -- Alice generates 8 sending keys
  (aliceKeys, aliceR1) <-
    expectRight $ runRatchetM @TestImplementation aliceR0 $ replicateM 8 $ ratchetSendingChainKey
  length aliceKeys `shouldBe` 8
  -- Alice has reached her maximum chain length. An attempt to generate another key...
  let aliceKey9 = runRatchetM @TestImplementation aliceR1 $ ratchetSendingChainKey
  -- ... should fail.
  aliceKey9 `shouldBe` Left MaxChainLengthReached

postMaxChainLengthReached :: IO ()
postMaxChainLengthReached = do
  -- Generate keys
  (aliceSec0, _) <- ToyCrypto.genKeyPair
  (_, bobPub0) <- ToyCrypto.genKeyPair
  -- Initialize double ratchet
  let aliceR0 = initializeRatchetState @TestImplementation bobPub0 aliceSec0 aliceAlicePov bobAlicePov
  -- Alice generates 8 sending keys
  (aliceKeys, aliceR1) <-
    expectRight $ runRatchetM @TestImplementation aliceR0 $ replicateM 8 $ ratchetSendingChainKey
  length aliceKeys `shouldBe` 8
  -- Alice has reached her maximum chain length. An attempt to generate another key...
  let aliceKey9 = runRatchetM @TestImplementation aliceR1 $ ratchetSendingChainKey
  -- ... should fail.
  aliceKey9 `shouldBe` Left MaxChainLengthReached
  -- Alice ratchets her root key
  (aliceSec1, _) <- ToyCrypto.genKeyPair
  (_, aliceR3) <-
    expectRight $ runRatchetM @TestImplementation aliceR1 $ advanceRootKey aliceSec1 aliceAlicePov bobAlicePov
  -- Alice can generate sending keys from the new chain key
  (aliceKeys2, _) <-
    expectRight $ runRatchetM @TestImplementation aliceR3 $ replicateM 5 $ ratchetSendingChainKey
  length aliceKeys2 `shouldBe` 5

aliceAlicePov, bobBobPov :: ToyCrypto.OurUserId
(aliceAlicePov, bobBobPov) = (ToyCrypto.OurUserId "alice", ToyCrypto.OurUserId "bob")

bobAlicePov, aliceBobPov :: ToyCrypto.TheirUserId
(bobAlicePov, aliceBobPov) = (ToyCrypto.TheirUserId "bob", ToyCrypto.TheirUserId "alice")

filterNotFound :: [(a, Maybe b)] -> [(a, b)]
filterNotFound = catMaybes . fmap (\(a, b) -> case b of Nothing -> Nothing; Just b' -> Just (a, b'))

expectRight :: Show l => Either l r -> IO r
expectRight = \case
  Left l -> assertFailure $ "Expected Right, but got Left: " <> show l
  Right r -> pure r

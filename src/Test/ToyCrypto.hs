{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE OverloadedStrings #-}

module Test.ToyCrypto
  ( toPublic
  , dh
  , genSecret
  , genKeyPair
  , SecretKey
  , PublicKey
  , initializeRoot
  , deriveNextSendingChain
  , deriveNextReceivingChain
  , deriveNextRootReceiving
  , deriveNextRootSending
  , aliceAlicePov
  , bobAlicePov
  , bobBobPov
  , aliceBobPov
  , OurUserId (..)
  , TheirUserId (..)
  , SendingChain
  , ReceivingChain
  , SymmetricKey
  , SharedSecret
  , Root
  )
where

import Data.Text (Text)
import Data.Text qualified as Text
import System.Random.Stateful (UniformRange (uniformRM), globalStdGen)

newtype SecretKey = SecretKey Integer
  deriving newtype Show

genSecret :: IO SecretKey
genSecret = fmap SecretKey $ uniformRM (2, 1000000) globalStdGen

newtype PublicKey = PublicKey Integer
  deriving newtype (Eq, Ord, Show)

toPublic :: SecretKey -> PublicKey
toPublic (SecretKey secret) = PublicKey $ (g ^ secret) `mod` p

genKeyPair :: IO (SecretKey, PublicKey)
genKeyPair = fmap (\sec -> (sec, toPublic sec)) genSecret

newtype SharedSecret = SharedSecret Integer
  deriving newtype Show

dh :: PublicKey -> SecretKey -> SharedSecret
dh (PublicKey public) (SecretKey secret) = SharedSecret $ (public ^ secret) `mod` p

p, g :: Integer
(p, g) = (2749, 71)

newtype OurUserId = OurUserId Text
  deriving newtype Show

newtype TheirUserId = TheirUserId Text
  deriving newtype Show

newtype Root = Root Text
  deriving newtype (Eq, Show)

newtype SendingChain = SendingChain Text
  deriving newtype Show

newtype ReceivingChain = ReceivingChain Text
  deriving newtype Show

initializeRoot :: OurUserId -> TheirUserId -> SharedSecret -> (Root, SendingChain, ReceivingChain)
initializeRoot (OurUserId ourId) (TheirUserId theirId) (SharedSecret secret) =
  ( Root $ pipeSep ["root", Text.show secret]
  , SendingChain $ pipeSep ["send", Text.show secret, ourId, theirId, "0"]
  , ReceivingChain $ pipeSep ["recv", Text.show secret, theirId, ourId, "0"]
  )

deriveNextRootReceiving :: Root -> OurUserId -> TheirUserId -> SharedSecret -> (Root, ReceivingChain)
deriveNextRootReceiving (Root root) (OurUserId ourId) (TheirUserId theirId) (SharedSecret secret) =
  case Text.split (== '|') root of
    ["root", accSecret] ->
      ( Root $ pipeSep ["root", accSecret <> Text.show secret]
      , ReceivingChain $ pipeSep ["recv", accSecret <> Text.show secret, theirId, ourId, "0"]
      )
    _ -> error "Bad root"

deriveNextRootSending :: Root -> OurUserId -> TheirUserId -> SharedSecret -> (Root, SendingChain)
deriveNextRootSending (Root root) (OurUserId ourId) (TheirUserId theirId) (SharedSecret secret) =
  case Text.split (== '|') root of
    ["root", accSecret] ->
      ( Root $ pipeSep ["root", accSecret <> Text.show secret]
      , SendingChain $ pipeSep ["send", accSecret <> Text.show secret, ourId, theirId, "0"]
      )
    _ -> error "Bad root"

newtype SymmetricKey = SymmetricKey Text
  deriving newtype (Eq, Ord, Show)

deriveNextSendingChain :: SendingChain -> (SymmetricKey, SendingChain)
deriveNextSendingChain (SendingChain sendingChain) =
  case Text.split (== '|') sendingChain of
    ["send", secret, ourId, theirId, msgSeq] ->
      ( SymmetricKey $ pipeSep ["symmKey", secret, ourId, theirId, msgSeq]
      , SendingChain $ pipeSep ["send", secret, ourId, theirId, Text.show (1 + (read $ Text.unpack msgSeq :: Integer))]
      )
    _ -> error "Bad sending chain"

deriveNextReceivingChain :: ReceivingChain -> (SymmetricKey, ReceivingChain)
deriveNextReceivingChain (ReceivingChain receivingChain) =
  case Text.split (== '|') receivingChain of
    ["recv", secret, their, our, msgSeq] ->
      ( SymmetricKey $ pipeSep ["symmKey", secret, their, our, msgSeq]
      , ReceivingChain $ pipeSep ["recv", secret, their, our, Text.show (1 + (read $ Text.unpack msgSeq :: Integer))]
      )
    _ -> error "Bad receiving chain"

aliceAlicePov, bobBobPov :: OurUserId
(aliceAlicePov, bobBobPov) = (OurUserId "alice", OurUserId "bob")

bobAlicePov, aliceBobPov :: TheirUserId
(bobAlicePov, aliceBobPov) = (TheirUserId "bob", TheirUserId "alice")

pipeSep :: [Text] -> Text
pipeSep = Text.intercalate "|"

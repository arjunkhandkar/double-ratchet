{- |
Module: DoubleRatchet
Copyright: (c) 2026 Arjun Khandkar
License: MIT
Maintainer: khandkararjun@gmail.com
Stability: experimental

This module exposes the minimum sufficient API needed to incorporate the double ratchet state machine provided
by this package into your projects.

If your use cases aren't satisfied by what this module exports, you may want to look at "DoubleRatchet.RatchetM"
or "DoubleRatchet.State".
-}
module DoubleRatchet
--

  ( -- * Implementing a double ratchet

    {- | The 'DoubleRatchet' class must be instantiated to use the state machine provided by this package.

    Wrangle your KDF primitives to fit the signatures in the class. The primitives must be cryptographically
    sound; the state machine simply makes do with whatever it has been provided.

    Note that class accepts pure primitives, which is by design as the state machine is deterministic.
    -}
    DoubleRatchet (..)

    -- * Ratchet state
  , RatchetState

    -- ** Inspecting ratchet state

  --

    {- | These have been exported as they may be necessary to implement a higher-level protocol that
    builds on top of the double ratchet algorithm.
    -}
  , getCurrentSendingChainLength

    -- * State transitions

  --

    {- | State transitions are of type 'RatchetM', which is an alias for 'State'. They can be executed using
    'runRatchetM' along with an explicit type application to point to your implementation:

    @
    let aliceR1 = runRatchetM @TestImplementation aliceR0 ratchetSendingChainKey
    @
    -}
  , runRatchetM
  , ratchetReceivingChainKey
  , ratchetSendingChainKey
  , advanceRootKey
  )
where

import DoubleRatchet.Class (DoubleRatchet (..))
import DoubleRatchet.RatchetM
  ( advanceRootKey
  , ratchetReceivingChainKey
  , ratchetSendingChainKey
  , runRatchetM
  )
import DoubleRatchet.State (RatchetState, getCurrentSendingChainLength)

{-# LANGUAGE TypeFamilies #-}

module Pos.Client.Txp.Addresses
       ( MonadAddresses (..)
       ) where

import           Universum

import           Pos.Core (Address)

-- | A class which have the method to generate a new address
class Monad m => MonadAddresses m where
    type AddrData m :: *

    -- | Generate new address using given 'AddrData' (e.g. password +
    -- account id).
    getNewAddress :: Maybe Int32 -> AddrData m -> m Address

    -- | Generate a “fake” change address. Its size must be greater
    -- than or equal to the maximal possible size of address generated
    -- by 'getNewAddress'.
    getFakeChangeAddress :: Maybe Int32 -> m Address

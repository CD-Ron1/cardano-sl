-- | General purpose utility functions
module Cardano.Wallet.Kernel.Util (
    -- * Lists
    at
  , neHead
    -- * Maps and sets
  , disjoint
  , withoutKeys
  , restrictKeys
  , markMissingMapEntries
    -- * Dealing with OldestFirst/NewestFirst
  , liftOldestFirstF
  , liftNewestFirstF
  , liftOldestFirst
  , liftNewestFirst
    -- * Probabilities
  , Probability
  , toss
    -- * MonadState utilities
  , modifyAndGetOld
  , modifyAndGetNew
  ) where

import           Universum

import qualified Data.Map.Merge.Strict as Map.Merge
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import           Pos.Core.Chrono
import qualified Test.QuickCheck as QC

{-------------------------------------------------------------------------------
  Lists
-------------------------------------------------------------------------------}

-- | Safe version of (!!)
at :: [a] -> Int -> Maybe a
at []     _ = Nothing
at (x:_)  0 = Just x
at (_:xs) i = at xs (i - 1)

neHead :: Lens' (NonEmpty a) a
neHead f (x :| xs) = (:| xs) <$> f x

{-------------------------------------------------------------------------------
  Maps and sets
-------------------------------------------------------------------------------}

-- | Check that two sets are disjoint
--
-- This is available out of the box from containters >= 0.5.11
disjoint :: Ord a => Set a -> Set a -> Bool
disjoint a b = Set.null (a `Set.intersection` b)

withoutKeys :: Ord k => Map k a -> Set k -> Map k a
m `withoutKeys` s = m `Map.difference` Map.fromSet (const ()) s

restrictKeys :: Ord k => Map k a -> Set k -> Map k a
m `restrictKeys` s = m `Map.intersection` Map.fromSet (const ()) s

-- | @markMissingMapEntries mustExist@ adds a 'Nothing' value for each key
-- in @mustExist@ that doesn't exist in the input map.
markMissingMapEntries :: Ord k => Map k b -> Map k a -> Map k (Maybe a)
markMissingMapEntries =
    Map.Merge.merge
      (Map.Merge.mapMaybeMissing     $ \_k _b   -> Just $ Nothing)
      (Map.Merge.mapMaybeMissing     $ \_k    a -> Just $ Just a)
      (Map.Merge.zipWithMaybeMatched $ \_k _b a -> Just $ Just a)

{-------------------------------------------------------------------------------
  Dealing with OldestFirst/NewestFirst
-------------------------------------------------------------------------------}

liftOldestFirstF :: Functor m
                 => (f a -> m (f a))
                 -> OldestFirst f a -> m (OldestFirst f a)
liftOldestFirstF f = fmap OldestFirst . f . getOldestFirst

liftNewestFirstF :: Functor m
                 => (f a -> m (f a))
                 -> NewestFirst f a -> m (NewestFirst f a)
liftNewestFirstF f = fmap NewestFirst . f . getNewestFirst

liftOldestFirst :: (f a -> f a) -> OldestFirst f a -> OldestFirst f a
liftOldestFirst f = runIdentity . liftOldestFirstF (Identity . f)

liftNewestFirst :: (f a -> f a) -> NewestFirst f a -> NewestFirst f a
liftNewestFirst f = runIdentity . liftNewestFirstF (Identity . f)

{-------------------------------------------------------------------------------
  Probabilities
-------------------------------------------------------------------------------}

-- | Probability (value between 0 and 1)
type Probability = Double

-- | Weighted coin toss
--
-- @toss p@ throws a p-weighted coin and returns whether it came up heads.
-- @toss 0@ will always return @False@, @toss 1@ will always return @True@.
toss :: Probability -> QC.Gen Bool
toss 0 = return False
toss 1 = return True
toss p = (< p) <$> QC.choose (0, 1)

{-------------------------------------------------------------------------------
  Access and return the state
-------------------------------------------------------------------------------}

-- | Modify the state and return the new state
modifyAndGetNew :: MonadState s m => (s -> s) -> m s
modifyAndGetNew f = state $ \old -> let new = f old in (new, new)

-- | Modify the state and return the old state
modifyAndGetOld :: MonadState s m => (s -> s) -> m s
modifyAndGetOld f = state $ \old -> let new = f old in (old, new)

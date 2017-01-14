{-# LANGUAGE ConstraintKinds     #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell     #-}
{-# LANGUAGE TypeFamilies        #-}

-- | All logic of certificates processing

module Pos.Delegation.Logic
       (
       -- * Helpers
         DelegationStateAction(..)
       , runDelegationStateAction
       , invalidateProxyCaches

       -- * Heavyweight psks handling
       , getProxyMempool
       , PskSimpleVerdict (..)
       , processProxySKSimple
       , delegationApplyBlocks
       , delegationVerifyBlocks
       , delegationRollbackBlocks

       -- * Lightweight psks handling
       , PskEpochVerdict (..)
       , processProxySKEpoch

       -- * Confirmations
       , ConfirmPskEpochVerdict (..)
       , processConfirmProxySk
       , isProxySKConfirmed
       ) where

import           Control.Concurrent.STM.TVar (readTVar, writeTVar)
import           Control.Lens                (makeLenses, use, uses, view, (%=), (.=),
                                              (^.))
import           Control.Monad.Trans.Except  (runExceptT, throwE)
import qualified Data.HashMap.Strict         as HM
import qualified Data.HashSet                as HS
import           Data.List                   (partition)
import           Data.List.NonEmpty          (NonEmpty)
import qualified Data.List.NonEmpty          as NE
import qualified Data.Text.Buildable         as B
import           Data.Time.Clock             (UTCTime, addUTCTime, getCurrentTime)
import           Formatting                  (bprint, build, sformat, stext, (%))
import           System.Wlog                 (WithLogger)
import           Universum

import           Pos.Binary.Communication    ()
import           Pos.Context                 (WithNodeContext (getNodeContext),
                                              lrcActionOnEpochReason, ncSecretKey)
import           Pos.Crypto                  (ProxySecretKey (..), PublicKey,
                                              pdDelegatePk, proxyVerify, shortHashF,
                                              toPublic, verifyProxySecretKey)
import           Pos.DB                      (DBError (DBMalformed), MonadDB,
                                              SomeBatchOp (..))
import qualified Pos.DB                      as DB
import qualified Pos.DB.GState               as GS
import qualified Pos.DB.Lrc                  as LrcDB
import qualified Pos.DB.Misc                 as Misc
import           Pos.Delegation.Class        (DelegationWrap, MonadDelegation (..),
                                              dwProxyConfCache, dwProxyMsgCache,
                                              dwProxySKPool)
import           Pos.Delegation.Types        (SendProxySK (..))
import           Pos.Ssc.Class               (Ssc)
import           Pos.Types                   (Block, Blund, NEBlocks, ProxySKEpoch,
                                              ProxySKSimple, ProxySigEpoch,
                                              Undo (undoPsk), addressHash, blockProxySKs,
                                              epochIndexL, headerHash, prevBlockL)
import           Pos.Util                    (_neHead)


----------------------------------------------------------------------------
-- Different helpers to simplify logic
----------------------------------------------------------------------------

-- | Convenient monad to work in 'DelegationWrap' context while being
-- in STM.
newtype DelegationStateAction a = DelegationStateAction
    { getDelegationStateM :: StateT DelegationWrap STM a
    } deriving (Functor, Applicative, Monad, MonadState DelegationWrap)

-- | Effectively takes a lock on ProxyCaches mvar in NodeContext and
-- allows you to run some computation producing updated ProxyCaches
-- and return value. Will put MVar back on exception.
runDelegationStateAction
    :: (MonadIO m, MonadDelegation m)
    => DelegationStateAction a -> m a
runDelegationStateAction action = do
    var <- askDelegationState
    atomically $ do
        startState <- readTVar var
        (res,newState)<- runStateT (getDelegationStateM action) startState
        writeTVar var newState
        pure res

-- | Invalidates proxy caches using built-in constants.
invalidateProxyCaches :: UTCTime -> DelegationStateAction ()
invalidateProxyCaches curTime = do
    dwProxyMsgCache %= HM.filter (\t -> addUTCTime 60 t > curTime)
    dwProxyConfCache %= HM.filter (\t -> addUTCTime 500 t > curTime)

type DelegationWorkMode ssc m = (MonadDelegation m, MonadDB ssc m, WithLogger m)

----------------------------------------------------------------------------
-- Exceptions
----------------------------------------------------------------------------

data DelegationError =
    -- | Can't apply blocks to state of transactions processing.
    DelegationCantApplyBlocks Text
    deriving (Show)

instance Exception DelegationError

instance B.Buildable DelegationError where
    build (DelegationCantApplyBlocks msg) =
        bprint ("can't apply in delegation module: "%stext) msg

----------------------------------------------------------------------------
-- Heavyweight PSK
----------------------------------------------------------------------------

-- | Retrieves current mempool of heavyweight psks plus undo part.
getProxyMempool
    :: (MonadDB ssc m, MonadDelegation m)
    => m ([ProxySKSimple], [ProxySKSimple])
getProxyMempool = do
    sks <- runDelegationStateAction $ uses dwProxySKPool HM.elems
    let issuers = map pskIssuerPk sks
    toRollback <- catMaybes <$> mapM GS.getPSKByIssuer issuers
    pure (sks, toRollback)

-- | Datatypes representing a verdict of simple PSK processing.
data PskSimpleVerdict
    = PSExists    -- ^ If we have exactly the same cert in psk mempool
    | PSForbidden -- ^ Not enough stake
    | PSInvalid   -- ^ Broken
    | PSCached    -- ^ Message is cached
    | PSAdded     -- ^ Successfully processed/added to psk mempool
    deriving (Show,Eq)

-- | Processes simple (hardweight) psk. Puts it into the mempool not
-- (TODO) depending on issuer's stake, overrides if exists, checks
-- validity and cachemsg state.
processProxySKSimple
    :: (Ssc ssc, MonadDB ssc m, MonadDelegation m, WithNodeContext ssc m)
    => ProxySKSimple -> m PskSimpleVerdict
processProxySKSimple psk = do
    curTime <- liftIO getCurrentTime
    headEpoch <- view epochIndexL <$> DB.getTipBlockHeader
    richmen <-
        NE.toList <$>
        lrcActionOnEpochReason
        headEpoch
        "Delegation.Logic#processProxySKSimple: there are no richmen for current epoch"
        LrcDB.getRichmenDlg
    let msg = SendProxySKSimple psk
        valid = verifyProxySecretKey psk
        issuer = pskIssuerPk psk
        enoughStake = addressHash issuer `elem` richmen
    runDelegationStateAction $ do
        exists <- uses dwProxySKPool $ \m -> HM.lookup issuer m == Just psk
        cached <- uses dwProxyMsgCache $ HM.member msg
        dwProxyMsgCache %= HM.insert msg curTime
        unless exists $ dwProxySKPool %= HM.insert issuer psk
        pure $ if | not valid -> PSInvalid
                  | not enoughStake -> PSForbidden
                  | cached -> PSCached
                  | exists -> PSExists
                  | otherwise -> PSAdded

-- state needed for 'delegationVerifyBlocks'
data DelVerState = DelVerState
    { _dvCurEpoch      :: HashSet PublicKey
      -- ^ Set of issuers that have already posted certificates this epoch
    , _dvPSKMapAdded   :: HashMap PublicKey ProxySKSimple
      -- ^ Psks added to database.
    , _dvPSKSetRemoved :: HashSet PublicKey
      -- ^ Psks removed from database.
    }

makeLenses ''DelVerState

-- | Verifies if blocks are correct relatively to the delegation logic
-- an returns non-empty list of proxySKs needed for undoing
-- them. Predicate for correctness here is:
-- * Issuer can post only one cert per epoch
-- * For every new certificate issuer had enough state at the
--   end of prev. epoch
--
-- Blocks are assumed to be oldest-first. It's assumed blocks are
-- correct from 'Pos.Types.Block#verifyBlocks' point of view.
delegationVerifyBlocks
    :: forall ssc m. (Ssc ssc, MonadDB ssc m, WithNodeContext ssc m)
    => NEBlocks ssc -> m (Either Text (NonEmpty [ProxySKSimple]))
delegationVerifyBlocks blocks = do
    -- TODO CSL-502 create snapshot
    -- TODO CSL-505 check that no two block have different epoch
    tip <- GS.getTip
    fromGenesisPsks <-
        concatMap (either (const []) (map pskIssuerPk . view blockProxySKs)) <$>
        DB.loadBlocksWhile isRight tip
    let _dvCurEpoch = HS.fromList fromGenesisPsks
        initState = DelVerState _dvCurEpoch HM.empty HS.empty
    richmen <-
        HS.fromList . NE.toList <$>
        lrcActionOnEpochReason
        headEpoch
        "Delegation.Logic#delegationVerifyBlocks: there are no richmen for current epoch"
        LrcDB.getRichmenDlg
    when (HS.size _dvCurEpoch /= length fromGenesisPsks) $
        throwM $ DBMalformed "Multiple stakeholders have issued & published psks this epoch"
    res <- evalStateT (runExceptT $ mapM (verifyBlock richmen) blocks) initState
    pure $ NE.reverse <$> res
  where
    headEpoch = view epochIndexL $ NE.head blocks
    withMapResolve issuer = do
        isAddedM <- uses dvPSKMapAdded $ HM.lookup issuer
        isRemoved <- uses dvPSKSetRemoved $ HS.member issuer
        if isRemoved
        then pure Nothing
        else maybe (GS.getPSKByIssuer issuer) (pure . Just) isAddedM
    withMapAdd psk = do
        let issuer = pskIssuerPk psk
        dvPSKMapAdded %= HM.insert issuer psk
        dvPSKSetRemoved %= HS.delete issuer
    withMapRemove issuer = do
        inAdded <- uses dvPSKMapAdded $ HM.member issuer
        if inAdded
        then dvPSKMapAdded %= HM.delete issuer
        else dvPSKSetRemoved %= HS.insert issuer
    verifyBlock _ (Left _) = do
        dvCurEpoch .= HS.empty
        pure []
    verifyBlock richmen (Right blk) = do
        let proxySKs = view blockProxySKs blk
            issuers = map pskIssuerPk proxySKs
        when (any (not . (`HS.member` richmen) . addressHash) issuers) $
            throwE $ sformat ("Block "%build%" contains psk issuers that "%
                              "don't have enough stake")
                             (headerHash blk)
        curEpoch <- use dvCurEpoch
        when (any (`HS.member` curEpoch) issuers) $
            throwE $ sformat ("Block "%build%" contains issuers that "%
                              "have already published psk this epoch")
                             (headerHash blk)
        -- we believe issuers list doesn't contain duplicates,
        -- checked in Types.Block#verifyBlocks
        dvCurEpoch %= HS.union (HS.fromList issuers)
        let toUpdate =
                filter (\ProxySecretKey{..} -> pskIssuerPk /= pskDelegatePk) proxySKs
        toRollback <- catMaybes <$> mapM withMapResolve issuers
        mapM_ withMapRemove issuers
        mapM_ withMapAdd toUpdate
        pure toRollback

-- | Applies a sequence of definitely valid blocks to memory state and
-- returns batchops.
delegationApplyBlocks
    :: forall ssc m. (DelegationWorkMode ssc m)
    => NonEmpty (Block ssc) -> m (NonEmpty SomeBatchOp)
delegationApplyBlocks blocks = do
    tip <- GS.getTip
    let assumedTip = blocks ^. _neHead . prevBlockL
    when (tip /= assumedTip) $ throwM $
        DelegationCantApplyBlocks $
        sformat
        ("Oldest block is based on tip "%shortHashF%", but our tip is "%shortHashF)
        assumedTip tip
    let allIssuers =
            concatMap (either (const []) (map pskIssuerPk . view blockProxySKs))
                      blocks
    runDelegationStateAction $
        forM_ allIssuers $ \i -> dwProxySKPool %= HM.delete i
    pure $ map applyBlock blocks
  where
    applyBlock :: Block ssc -> SomeBatchOp
    applyBlock (Left _)      = SomeBatchOp ([]::[GS.DelegationOp])
    applyBlock (Right block) = do
        let proxySKs = view blockProxySKs block
            (toDelete,toReplace) =
                partition (\ProxySecretKey{..} -> pskIssuerPk == pskDelegatePk)
                proxySKs
        SomeBatchOp $
            map (GS.DelPSK . pskIssuerPk) toDelete ++ map GS.AddPSK toReplace

-- | Rollbacks block list. Erases mempool of certificates. Better to
-- restore them after the rollback (see Txp#normalizeTxpLD).
delegationRollbackBlocks
    :: (MonadDelegation m, MonadIO m)
    => NonEmpty (Blund ssc) -> m (NonEmpty SomeBatchOp)
delegationRollbackBlocks blunds = do
    runDelegationStateAction $ dwProxySKPool .= HM.empty
    pure $ map rollbackBlund blunds
  where
    rollbackBlund :: Blund ssc -> SomeBatchOp
    rollbackBlund (Left _, _) = SomeBatchOp ([]::[GS.DelegationOp])
    rollbackBlund (Right block, undo) =
        let proxySKs = view blockProxySKs block
            toReplace =
                map pskIssuerPk $
                filter (\ProxySecretKey{..} -> pskIssuerPk /= pskDelegatePk)
                proxySKs
            toDeleteBatch = map GS.DelPSK toReplace
            toAddBatch = map GS.AddPSK $ undoPsk undo
        in SomeBatchOp $ toDeleteBatch ++ toAddBatch


----------------------------------------------------------------------------
-- Lightweight PSK propagation
----------------------------------------------------------------------------

-- | PSK check verdict. It can be unrelated (other key or spoiled, no
-- way to differ), exist in storage already or be cached.
data PskEpochVerdict
    = PEUnrelated
    | PEInvalid
    | PEExists
    | PECached
    | PERemoved
    | PEAdded
    deriving (Show,Eq)

-- TODO Calls to DB are not synchronized for now, because storage is
-- append-only, so nothing bad should happen. But it may be a problem
-- later.
-- | Processes proxy secret key (understands do we need it,
-- adds/caches on decision, returns this decision).
processProxySKEpoch
    :: (MonadDelegation m, WithNodeContext ssc m, MonadDB ssc m)
    => ProxySKEpoch -> m PskEpochVerdict
processProxySKEpoch psk = do
    sk <- ncSecretKey <$> getNodeContext
    curTime <- liftIO getCurrentTime
    -- (1) We're reading from DB
    psks <- Misc.getProxySecretKeys
    res <- runDelegationStateAction $ do
        let related = toPublic sk == pskDelegatePk psk
            exists = psk `elem` psks
            msg = SendProxySKEpoch psk
            valid = verifyProxySecretKey psk
            selfSigned = pskDelegatePk psk == pskIssuerPk psk
        cached <- uses dwProxyMsgCache $ HM.member msg
        dwProxyMsgCache %= HM.insert msg curTime
        pure $ if | not valid -> PEInvalid
                  | cached -> PECached
                  | exists -> PEExists
                  | selfSigned -> PERemoved
                  | not related -> PEUnrelated
                  | otherwise -> PEAdded
    -- (2) We're writing to DB
    when (res == PEAdded) $ Misc.addProxySecretKey psk
    when (res == PERemoved) $ Misc.removeProxySecretKey $ pskIssuerPk psk
    pure res

----------------------------------------------------------------------------
-- Lightweight PSK confirmation backpropagation
----------------------------------------------------------------------------

-- | Verdict of 'processConfirmProxySk' function
data ConfirmPskEpochVerdict
    = CPValid   -- ^ Valid, saved
    | CPInvalid -- ^ Invalid, throw away
    | CPCached  -- ^ Already saved
    deriving (Show,Eq)

-- | Takes a lightweight psk, delegate proof of delivery. Checks if
-- it's valid or not. Caches message in any case.
processConfirmProxySk
    :: (MonadDelegation m, MonadIO m)
    => ProxySKEpoch -> ProxySigEpoch ProxySKEpoch -> m ConfirmPskEpochVerdict
processConfirmProxySk psk proof = do
    curTime <- liftIO getCurrentTime
    runDelegationStateAction $ do
        let valid = proxyVerify (pdDelegatePk proof) proof (const True) psk
        cached <- uses dwProxyConfCache $ HM.member psk
        when valid $ dwProxyConfCache %= HM.insert psk curTime
        pure $ if | cached -> CPCached
                  | not valid -> CPInvalid
                  | otherwise -> CPValid

-- | Checks if we hold a confirmation for given PSK.
isProxySKConfirmed :: ProxySKEpoch -> DelegationStateAction Bool
isProxySKConfirmed psk = uses dwProxyConfCache $ HM.member psk

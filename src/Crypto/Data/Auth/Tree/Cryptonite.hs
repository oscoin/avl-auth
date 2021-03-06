module Crypto.Data.Auth.Tree.Cryptonite
    ( hashLeaf
    , concatHashes
    , emptyHash
    ) where

import           Prelude

import           Crypto.Hash
                 ( Digest
                 , HashAlgorithm
                 , digestFromByteString
                 , hashDigestSize
                 , hashFinalize
                 , hashInit
                 , hashUpdate
                 , hashUpdates
                 )
import qualified Crypto.Hash as Cryptonite
import           Data.ByteArray (ByteArrayAccess, zero)
import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import           Data.Maybe (fromJust)

hashLeaf
    :: (HashAlgorithm a, ByteArrayAccess k, ByteArrayAccess v)
    => k -> v -> Digest a
hashLeaf k v =
    hashFinalize $ flip hashUpdate v
                 $ flip hashUpdate k
                 $ flip hashUpdate (BS.singleton 0)
                 $ hashInit
concatHashes
    :: HashAlgorithm a
    => Digest a -> Digest a -> Digest a
concatHashes l r =
    hashFinalize $ flip hashUpdates [l, r]
                 $ flip hashUpdate (BS.singleton 1)
                 $ hashInit

emptyHash :: forall a. HashAlgorithm a => Digest a
emptyHash =
    fromJust $ digestFromByteString (zero n :: ByteString)
  where
    n = hashDigestSize (undefined :: a)


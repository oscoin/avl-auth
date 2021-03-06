module Crypto.Data.Auth.Tree.Class where

import           Prelude

import           Crypto.Hash
                 ( digestFromByteString
                 , hashDigestSize
                 , hashFinalize
                 , hashInit
                 , hashUpdate
                 , hashUpdates
                 )
import           Data.ByteArray (ByteArrayAccess, zero)
import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import           Data.Maybe (fromJust)

-- | A typeclass abstracting over the particular hashing function (and
-- digest) used in the Merkle Tree.
class MerkleHash h where
    emptyHash :: h

    -- | Given a key and a value, hash them to produce a leaf.
    -- NOTE: It's up to the implementer of a particular instance to deal with
    -- security concerns and make sure this implementation is not subject to
    -- attacks. The 'Cryptonite' implementation takes care of this already,
    -- but new instances should be implemened with this in mind.
    hashLeaf :: forall k v. (ByteArrayAccess k, ByteArrayAccess v) => k -> v -> h

    -- | Hashes two nodes together, concatenating their hashes to produce a
    -- new one. Same security concerns of 'hashLeaf' applies.
    concatHashes :: h -> h -> h

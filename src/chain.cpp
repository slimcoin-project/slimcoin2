// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <util/time.h>

std::string CBlockFileInfo::ToString() const
{
    return strprintf("CBlockFileInfo(blocks=%u, size=%u, heights=%u...%u, time=%s...%s)", nBlocks, nSize, nHeightFirst, nHeightLast, FormatISO8601Date(nTimeFirst), FormatISO8601Date(nTimeLast));
}

void CChain::SetTip(CBlockIndex *pindex) {
    if (pindex == nullptr) {
        vChain.clear();
        return;
    }
    vChain.resize(pindex->nHeight + 1);
    while (pindex && vChain[pindex->nHeight] != pindex) {
        vChain[pindex->nHeight] = pindex;
        pindex = pindex->pprev;
    }
}

CBlockLocator CChain::GetLocator(const CBlockIndex *pindex) const {
    int nStep = 1;
    std::vector<uint256> vHave;
    vHave.reserve(32);

    if (!pindex)
        pindex = Tip();
    while (pindex) {
        vHave.push_back(pindex->GetBlockHash());
        // Stop when we have added the genesis block.
        if (pindex->nHeight == 0)
            break;
        // Exponentially larger steps back, plus the genesis block.
        int nHeight = std::max(pindex->nHeight - nStep, 0);
        if (Contains(pindex)) {
            // Use O(1) CChain index if possible.
            pindex = (*this)[nHeight];
        } else {
            // Otherwise, use O(log n) skiplist.
            pindex = pindex->GetAncestor(nHeight);
        }
        if (vHave.size() > 10)
            nStep *= 2;
    }

    return CBlockLocator(vHave);
}

const CBlockIndex *CChain::FindFork(const CBlockIndex *pindex) const {
    if (pindex == nullptr) {
        return nullptr;
    }
    if (pindex->nHeight > Height())
        pindex = pindex->GetAncestor(Height());
    while (pindex && !Contains(pindex))
        pindex = pindex->pprev;
    return pindex;
}

CBlockIndex* CChain::FindEarliestAtLeast(int64_t nTime, int height) const
{
    std::pair<int64_t, int> blockparams = std::make_pair(nTime, height);
    std::vector<CBlockIndex*>::const_iterator lower = std::lower_bound(vChain.begin(), vChain.end(), blockparams,
        [](CBlockIndex* pBlock, const std::pair<int64_t, int>& blockparams) -> bool { return pBlock->GetBlockTimeMax() < blockparams.first || pBlock->nHeight < blockparams.second; });
    return (lower == vChain.end() ? nullptr : *lower);
}

/** Turn the lowest '1' bit in the binary representation of a number into a '0'. */
int static inline InvertLowestOne(int n) { return n & (n - 1); }

/** Compute what height to jump back to with the CBlockIndex::pskip pointer. */
int static inline GetSkipHeight(int height) {
    if (height < 2)
        return 0;

    // Determine which height to jump back to. Any number strictly lower than height is acceptable,
    // but the following expression seems to perform well in simulations (max 110 steps to go back
    // up to 2**18 blocks).
    return (height & 1) ? InvertLowestOne(InvertLowestOne(height - 1)) + 1 : InvertLowestOne(height);
}

const CBlockIndex* CBlockIndex::GetAncestor(int height) const
{
    if (height > nHeight || height < 0) {
        return nullptr;
    }

    const CBlockIndex* pindexWalk = this;
    int heightWalk = nHeight;
    while (heightWalk > height) {
        int heightSkip = GetSkipHeight(heightWalk);
        int heightSkipPrev = GetSkipHeight(heightWalk - 1);
        if (pindexWalk->pskip != nullptr &&
            (heightSkip == height ||
             (heightSkip > height && !(heightSkipPrev < heightSkip - 2 &&
                                       heightSkipPrev >= height)))) {
            // Only follow pskip if pprev->pskip isn't better than pskip->pprev.
            pindexWalk = pindexWalk->pskip;
            heightWalk = heightSkip;
        } else {
            assert(pindexWalk->pprev);
            pindexWalk = pindexWalk->pprev;
            heightWalk--;
        }
    }
    return pindexWalk;
}

CBlockIndex* CBlockIndex::GetAncestor(int height)
{
    return const_cast<CBlockIndex*>(static_cast<const CBlockIndex*>(this)->GetAncestor(height));
}

void CBlockIndex::BuildSkip()
{
    if (pprev)
        pskip = pprev->GetAncestor(GetSkipHeight(nHeight));
}

/*arith_uint256 GetBlockTrust(const CBlockIndex& block)
/*{
    arith_uint256 bnTarget;
    bool fNegative;
    bool fOverflow;
    bnTarget.SetCompact(block.nBits, &fNegative, &fOverflow);
    if (fNegative || fOverflow || bnTarget == 0)
        return 0;
    // We need to compute 2**256 / (bnTarget+1), but we can't represent 2**256
    // as it's too large for an arith_uint256. However, as 2**256 is at least as large
    // as bnTarget+1, it is equal to ((2**256 - bnTarget - 1) / (bnTarget+1)) + 1,
    // or ~bnTarget / (bnTarget+1) + 1.
    return block.IsProofOfStake() ? (~bnTarget / (bnTarget + 1)) + 1 : 1;
}*/

//CBigNum CBlockIndex::GetBlockTrust() const
// as call is modified in PPC, we add block.X to IsProofOfStake/IsProofOfBurn, nBits, pprev
// SLM version is heavily modified, needs additional params
arith_uint256 GetBlockTrust(const CBlockIndex& block)
{
    /* New protocol */
    // bool fTestNet = params.strNetworkID != CBaseChainParams::MAIN // this seems to be the "official" way to look if it's mainnet or testnet
    bool fTestNet = true; // dirty workaround to get the program compiled first time, it anyway will only read testnet due to lack of dcrypt.
    if (fTestNet || block.GetBlockTime() > CHAINCHECKS_SWITCH_TIME) // declared in chain.h
    {

        arith_uint256 bnTarget; // was CBigNum
        // bnTarget.SetCompact(IsProofOfBurn() ? nBurnBits : nBits); // original SLM, temporarily deactivated PoB
        bool fNegative;
        bool fOverflow;
        bnTarget.SetCompact(block.nBits, &fNegative, &fOverflow);
        if (fNegative || fOverflow || bnTarget == 0)
            return 0;

        /*if (bnTarget <= 0)
            return 0;*/ // replaced by code before.

        // Calculate work amount for block
        // uint256 nBlkBase = IsProofOfBurn() ? nPoBBase : nPoWBase; // original SLM // IsProofOfBurn -> block.IsProofOfBurn
        uint256 nBlkBase = nPoWBaseTestnet; // modified SLM, PoB deactivated, only Testnet supported.
        // CBigNum nBlkTrust = CBigNum(nBlkBase) / (bnTarget + 1); // original SLM
        arith_uint256 nBlkTrust = UintToArith256(nBlkBase) / (bnTarget + 1);

        // Set nPowTrust to 1 if we are checking PoS block or PoW difficulty is too low
        nBlkTrust = (block.IsProofOfStake() || nBlkTrust < 1) ? 1 : nBlkTrust;

        // Return nBlkTrust for the first 12 blocks
        if (block.pprev == NULL || block.pprev->nHeight < 12)
            return nBlkTrust;

        const CBlockIndex* currentIndex = block.pprev;

        if (block.IsProofOfStake())
        {
            arith_uint256 bnNewTrust = (arith_uint256(1)<<256) / (bnTarget + 1);

            // Return 1/3 of score if parent block is not the PoW block
            if (!block.pprev->IsProofOfWork())
                return bnNewTrust / 3;

            int nPoWCount = 0;

            // Check last 12 blocks type
            while (block.pprev->nHeight - currentIndex->nHeight < 12)
            {
                if (currentIndex->IsProofOfWork())
                    nPoWCount++;
                currentIndex = currentIndex->pprev;
            }

            // Return 1/3 of score if less than 3 PoW blocks found
            if (nPoWCount < 3)
                return bnNewTrust / 3;

            return bnNewTrust;
        }
        else
        {
            arith_uint256 bnLastBlockTrust = arith_uint256(block.pprev->nChainTrust - block.pprev->pprev->nChainTrust); // bnChainTrust -> nChainTrust

            // Return nBlkTrust + 2/3 of previous block score if two parent blocks are not PoS blocks
            if (!(block.pprev->IsProofOfStake() && block.pprev->pprev->IsProofOfStake()))
                return nBlkTrust + (2 * bnLastBlockTrust / 3);

            int nPoSCount = 0;

            // Check last 12 blocks type
            while(block.pprev->nHeight - currentIndex->nHeight < 12)
            {
                if (currentIndex->IsProofOfStake())
                    nPoSCount++;
                currentIndex = currentIndex->pprev;
            }

            // Return nBlkTrust + 2/3 of previous block score if less than 7 PoS blocks found
            if (nPoSCount < 7)
                return nBlkTrust + (2 * bnLastBlockTrust / 3);

            // bnTarget.SetCompact(IsProofOfBurn() ? pprev->nBurnBits : pprev->nBits); // PoB disabled
            bnTarget.SetCompact(block.pprev->nBits);

            if (bnTarget <= 0)
                return 0;

            arith_uint256 bnNewTrust = (arith_uint256(1) << 256) / (bnTarget + 1);

            // Return nBlkTrust + full trust score for previous block nBits or nBurnBits
            return nBlkTrust + bnNewTrust;
        }

    }
    else
    {

        /* Old protocol */

        arith_uint256 bnTarget;
        bnTarget.SetCompact(block.nBits);

        if (bnTarget <= 0)
            return 0;

        return (block.IsProofOfStake() ? (arith_uint256(1) << 256) / (bnTarget + 1) : 1);
    }
}

int64_t GetBlockProofEquivalentTime(const CBlockIndex& to, const CBlockIndex& from, const CBlockIndex& tip, const Consensus::Params& params)
{
    arith_uint256 r;
    int sign = 1;
    if (to.nChainTrust > from.nChainTrust) {
        r = to.nChainTrust - from.nChainTrust;
    } else {
        r = from.nChainTrust - to.nChainTrust;
        sign = -1;
    }
    r = r * arith_uint256(params.nPowTargetSpacing) / GetBlockTrust(tip);
    if (r.bits() > 63) {
        return sign * std::numeric_limits<int64_t>::max();
    }
    return sign * int64_t(r.GetLow64());
}

/** Find the last common ancestor two blocks have.
 *  Both pa and pb must be non-nullptr. */
const CBlockIndex* LastCommonAncestor(const CBlockIndex* pa, const CBlockIndex* pb) {
    if (pa->nHeight > pb->nHeight) {
        pa = pa->GetAncestor(pb->nHeight);
    } else if (pb->nHeight > pa->nHeight) {
        pb = pb->GetAncestor(pa->nHeight);
    }

    while (pa != pb && pa && pb) {
        pa = pa->pprev;
        pb = pb->pprev;
    }

    // Eventually all chain branches meet at the genesis block.
    assert(pa == pb);
    return pa;
}

// peercoin: find last block index up to pindex
const CBlockIndex* GetLastBlockIndex(const CBlockIndex* pindex, bool fProofOfStake)
{
    while (pindex && pindex->pprev && (pindex->IsProofOfStake() != fProofOfStake))
        pindex = pindex->pprev;
    return pindex;
}

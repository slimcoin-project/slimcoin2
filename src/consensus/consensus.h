// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_CONSENSUS_H
#define BITCOIN_CONSENSUS_CONSENSUS_H

#include <stdlib.h>
#include <stdint.h>

/** The maximum allowed size for a serialized block, in bytes (only for buffer size limits) */
static const unsigned int MAX_BLOCK_SERIALIZED_SIZE = 4000000;
/** The maximum allowed weight for a block, see BIP 141 (network rule) */
static const unsigned int MAX_BLOCK_WEIGHT = 4000000;
/** The maximum allowed number of signature check operations in a block (network rule) */
static const int64_t MAX_BLOCK_SIGOPS_COST = 80000; // SLM originally has 1M/50, i.e. 20000. Due to weight increase * 4 it should be 80000 too.
/** Coinbase transaction outputs can only be spent after this number of new blocks (network rule) */
static const int COINBASE_MATURITY = 500; // PPC: 100

// from here not changed.

static const int WITNESS_SCALE_FACTOR = 4;

static const size_t MIN_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 60; // 60 is the lower bound for the size of a valid serialized CTransaction
static const size_t MIN_SERIALIZABLE_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 10; // 10 is the lower bound for the size of a serialized CTransaction

/** Flags for nSequence and nLockTime locks */
/** Interpret sequence numbers as relative lock-time constraints. */
static constexpr unsigned int LOCKTIME_VERIFY_SEQUENCE = (1 << 0);
/** Use GetMedianTimePast() instead of nTime for end point timestamp. */
static constexpr unsigned int LOCKTIME_MEDIAN_TIME_PAST = (1 << 1);

// SLM minor protocol switches of 2014. Look if there's a better place to place these.
// PPC protocol switch times are in kernel.cpp, but kernel.cpp should not be included in validation.cpp.
////////////////////////////////
//PATCHES
////////////////////////////////

//Rounds down the burn hash for all hashes after (or equalling) timestamp 1402314985, not really needed though
// has became a legacy thing due to the burn_hash_intermediate
const uint32_t BURN_ROUND_DOWN = 1402314985; //Mon, 09 Jun 2014 11:56:25 GMT  // was u32int

//Adjusts the trust values for PoW and PoB blocks => moved to chain.h
// const uint32_t CHAINCHECKS_SWITCH_TIME = 1407110400; //Mon, 04 Aug 2014 00:00:00 GMT // was uint64

//Adjusts PoB and PoS targets
const uint32_t POB_POS_TARGET_SWITCH_TIME = 1407110400; //Mon, 04 Aug 2014 00:00:00 GMT // was uint64

#endif // BITCOIN_CONSENSUS_CONSENSUS_H

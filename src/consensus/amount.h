// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_AMOUNT_H
#define BITCOIN_CONSENSUS_AMOUNT_H

#include <cstdint>
#include <string>

/** Amount in satoshis (Can be negative) */
typedef int64_t CAmount;

static constexpr CAmount COIN = 1000000;
static constexpr CAmount CENT = 10000;

static const CAmount MIN_TX_FEE_PREV7 = CENT; // SLM: we can probably keep this variable, as we'll not switch fast to protocolV7.
static const CAmount MIN_TX_FEE = CENT / 10;
static const CAmount PERKB_TX_FEE = CENT;
static const CAmount MIN_TXOUT_AMOUNT = CENT; // SLM: originally MIN_TX_FEE.
static const CAmount MAX_MINT_PROOF_OF_WORK = 50 * COIN; // PPC: 9999 * COIN
static const CAmount MAX_MINT_PROOF_OF_WORK_V10 = 50 * COIN; // SLM upgrade: this seems to be the amount after V10, but SLM has 50 also before v10.
static const std::string CURRENCY_UNIT = "SLM";
static const std::string CURRENCY_ATOM = "sat"; // One indivisible minimum value unit

/** No amount larger than this (in satoshi) is valid.
 *
 * Note that this constant is *not* the total money supply, which in Bitcoin
 * currently happens to be less than 21,000,000 BTC for various reasons, but
 * rather a sanity check. As this sanity check is used by consensus-critical
 * validation code, the exact value of the MAX_MONEY constant is consensus
 * critical; in unusual circumstances like a(nother) overflow bug that allowed
 * for the creation of coins out of thin air modification could lead to a fork.
 * */
static constexpr CAmount MAX_MONEY = 250000000 * COIN; // PPC: 21000000 * COIN
inline bool MoneyRange(const CAmount& nValue) { return (nValue >= 0 && nValue <= MAX_MONEY); }

#endif // BITCOIN_CONSENSUS_AMOUNT_H

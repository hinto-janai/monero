// PoWER uses Equi-X by tevador here:
// <https://github.com/tevador/equix/>.
//
// Equi-X is:
// Copyright (c) 2020 tevador <tevador@gmail.com>
//
// and licensed under the terms of the LGPL version 3.0:
// <https://www.gnu.org/licenses/lgpl-3.0.html>

// Copyright (c) 2019-2025, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#pragma once

//local headers
#include "crypto/hash.h"

//third party headers
#include <equix.h>

//standard headers
#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

//forward declarations

namespace tools
{
  // RPC related code apply to both the RPC and ZMQ-RPC interfaces.
  namespace power
  {
    // Input counts greater than this require PoWER.
    inline constexpr size_t INPUT_THRESHOLD = 8;

    // Number of recent block hashes viable for RPC.
    inline constexpr size_t HEIGHT_WINDOW = 2;

    // Fixed difficulty for valid PoW.
    // Target time = ~1s of single-threaded computation.
    //
    // The difficulty value and computation time
    // are directly proportional, in other words:
    // - `DIFFICULTY = 200` takes twice as long as
    // - `DIFFICULTY = 100` takes twice as long as
    // - `DIFFICULTY = 50` and so on
    //
    // Reference values; value of machines are measured in
    // seconds and rounded to the expected average given
    // enough computation:
    //
    // | Difficulty | Raspberry Pi 5 | Ryzen 5950x | Mac mini M4 |
    // |------------|----------------|-------------|-------------|
    // | 25         | 0.6            | 0.15        | 0.09        |
    // | 50         | 1.2            | 0.30        | 0.18        |
    // | 100        | 2.4            | 0.60        | 0.37        |
    // | 200        | 4.8            | 1.20        | 0.75        |
    // | 400        | 9.6            | 2.40        | 1.50        |
    inline constexpr size_t DIFFICULTY = 200;

    // Technically, nodes can be modified to send lower/higher difficulties in P2P.
    // A vanilla node will adjust accordingly; it can and will and solve a higher difficulty challenge.
    // This is the max valid difficulty requested from a peer before the connection is dropped.
    inline constexpr size_t MAX_DIFFICULTY = DIFFICULTY * 2;

    // Personalization string used in PoWER hashes.
    inline constexpr std::string_view PERSONALIZATION_STRING = "Monero PoWER";

    // (PERSONALIZATION_STRING || tx_prefix_hash || recent_block_hash || nonce)
    inline constexpr size_t CHALLENGE_SIZE_RPC =
      PERSONALIZATION_STRING.size() +
      sizeof(crypto::hash) +
      sizeof(crypto::hash) +
      sizeof(uint32_t);

    // (PERSONALIZATION_STRING || seed || seed_top64 || difficulty || nonce)
    inline constexpr size_t CHALLENGE_SIZE_P2P =
      PERSONALIZATION_STRING.size() +
      sizeof(uint64_t) +
      sizeof(uint64_t) +
      sizeof(uint32_t) +
      sizeof(uint32_t);

    static_assert(PERSONALIZATION_STRING.size() == 12, "Implementation assumes 12 bytes");
    static_assert(CHALLENGE_SIZE_RPC == 80, "Implementation assumes 80 bytes");
    static_assert(CHALLENGE_SIZE_P2P == 36, "Implementation assumes 36 bytes");
    static_assert(sizeof(crypto::hash) == 32, "Implementation assumes 32 bytes");
    static_assert(sizeof(std::array<uint16_t, 8>) == sizeof(equix_solution), "Implementation assumes 16 bytes");

    struct power_solution
    {
      std::vector<uint8_t> challenge;
      std::array<uint16_t, 8> solution;
      uint32_t nonce;
    };

    struct power_challenge_rpc {
      // Hash of transaction prefix.
      crypto::hash tx_prefix_hash;
      // Block hash within the last POWER_HEIGHT_WINDOW blocks.
      crypto::hash recent_block_hash;
      // A valid nonce.
      uint32_t nonce;
    };

    struct power_challenge_p2p {
      // Low bits of 128-bit seed.
      uint64_t seed;
      // High bits of 128-bit seed.
      uint64_t seed_top64;
      // Difficulty parameter from peer.
      uint32_t difficulty;
      // A valid nonce.
      uint32_t nonce;
    };

    // /**
    // * @brief Find an Equi-X solution to a challenge.
    // *
    // * @param challenge       Pointer to the challenge data.
    // * @param challenge_size  Size of the challenge.
    // *
    // * @return The solution if one is found, otherwise std::nullopt
    // */
    // std::optional<std::array<uint16_t, 8>> find_equix_solution(
    //   const void* challenge,
    //   const size_t challenge_size
    // );

    // /**
    // * @brief Verify an Equi-X solution.
    // *
    // * @param challenge       Challenge data.
    // * @param solution        The Equi-X solution to verify.
    // *
    // * @return true  – if verification succeeded
    // * @return false – if verification failed (invalid input, allocation error, difficulty too low).
    // */
    // template<std::size_t T>
    // bool verify_equix_solution(
    //   const std::array<std::uint8_t, T>& challenge,
    //   const std::array<uint16_t, 8> solution
    // );

    /**
    * @brief Create the difficulty scalar used for `check_difficulty`.
    *
    * @param challenge       Pointer to the challenge data.
    * @param challenge_size  Size of the challenge.
    * @param solution        An Equi-X solution.
    */
    uint32_t create_difficulty_scalar(
      const void* challenge,
      const size_t challenge_size,
      const std::array<uint16_t, 8> solution
    );

    /**
    * @brief Check if a PoWER solution satisfies a difficulty.
    *
    * @param scalar      The PoWER solution as a scalar using `create_difficulty_scalar`.
    * @param difficulty  The difficulty parameter.
    *
    * @return - true if the difficulty check passes, false otherwise.
    */
    bool check_difficulty(const uint32_t scalar, uint32_t difficulty);

    /**
    * @brief Create a PoWER challenge for RPC.
    *
    * @param tx_prefix_hash     Hash of transaction prefix.
    * @param recent_block_hash  Block hash within the last POWER_HEIGHT_WINDOW blocks.
    * @param nonce              The nonce parameter.
    *
    * @return PoWER RPC challenge as bytes.
    */
    std::array<std::uint8_t, CHALLENGE_SIZE_RPC> create_challenge_rpc(
      const crypto::hash tx_prefix_hash,
      const crypto::hash recent_block_hash,
      const uint32_t nonce
    ) noexcept;

    /**
    * @brief Create a PoWER challenge for P2P.
    *
    * @param seed        Low bytes of challenge seed.
    * @param seed_top64  High bytes of challenge seed.
    * @param difficulty  The difficulty parameter.
    * @param nonce       The nonce parameter.
    *
    * @return PoWER P2P challenge as bytes.
    */
    std::array<std::uint8_t, CHALLENGE_SIZE_P2P> create_challenge_p2p(
      const uint64_t seed,
      const uint64_t seed_top64,
      const uint32_t difficulty,
      const uint32_t nonce
    ) noexcept;

    /**
    * @brief Generate and solve a PoWER challenge for RPC for a given difficulty.
    *
    * @param tx_prefix_hash     Hash of transaction prefix.
    * @param recent_block_hash  Block hash within the last POWER_HEIGHT_WINDOW blocks.
    * @param difficulty         The difficulty parameter.
    */
    power_solution solve_rpc(
      const crypto::hash& tx_prefix_hash,
      const crypto::hash& recent_block_hash,
      const uint32_t difficulty
    );

    /**
    * @brief Generate and solve a PoWER challenge for P2P for a given difficulty.
    *
    * @param seed        Low bytes of challenge seed.
    * @param seed_top64  High bytes of challenge seed.
    * @param difficulty  The difficulty parameter.
    */
    power_solution solve_p2p(
      const uint64_t seed,
      const uint64_t seed_top64,
      const uint32_t difficulty
    );

    // /**
    // * @brief Verify a PoWER solution.
    // *
    // * @param challenge       Pointer to the challenge data.
    // * @param challenge_size  Size of the challenge.
    // * @param solution        The Equi-X solution.
    // * @param difficulty      The difficulty parameter.
    // *
    // * @return true - if the challenge and solution are well-formed, valid, and pass the difficulty.
    // * @return false – if verification failed (invalid input, allocation error, difficulty too low).
    // */
    // bool verify(
    //   const void* challenge,
    //   const size_t challenge_size,
    //   const uint32_t difficulty,
    //   const std::array<uint16_t, 8> solution
    // );

    /**
    * @brief Verify a PoWER solution for RPC.
    *
    * @param tx_prefix_hash     Hash of transaction prefix.
    * @param recent_block_hash  Block hash within the last POWER_HEIGHT_WINDOW blocks.
    * @param nonce              A valid nonce.
    * @param difficulty         The difficulty parameter.
    * @param solution           The Equi-X solution.
    *
    * @return true  – if verification succeeded
    * @return false – if verification failed (invalid input, allocation error, difficulty too low).
    */
    bool verify_rpc(
      const crypto::hash& tx_prefix_hash,
      const crypto::hash& recent_block_hash,
      const uint32_t nonce,
      const uint32_t difficulty,
      const std::array<uint16_t, 8> solution
    );

    /**
    * @brief Verify a PoWER solution for P2P.
    *
    * @param seed        Low bytes of challenge seed.
    * @param seed_top64  High bytes of challenge seed.
    * @param nonce       A valid nonce.
    * @param difficulty  The difficulty parameter.
    * @param solution    The Equi-X solution.
    *
    * @return true  – if verification succeeded
    * @return false – if verification failed (invalid input, allocation error, difficulty too low).
    */
    bool verify_p2p(
      const uint64_t seed,
      const uint64_t seed_top64,
      const uint32_t difficulty,
      const uint32_t nonce,
      const std::array<uint16_t, 8> solution
    );

  } // namespace power
} // namespace tools
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

//paired header
#include "power.h"

//local headers
#include "crypto/blake2b.h"
#include "int-util.h"

//third party headers
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/cpp_int/import_export.hpp>
#include <boost/multiprecision/integer.hpp>
#include <cstdlib>
#include <equix.h>

//standard headers
#include <array>
#include <cstdint>
#include <cstring>
#include <optional>

//forward declarations

namespace tools
{
  namespace power
  {
    using boost::multiprecision::uint128_t;

    namespace {
      std::array<uint16_t, 8> equix_solution_to_array(const equix_solution solution)
      {
        std::array<uint16_t, 8> s;
        memcpy(s.data(), solution.idx, sizeof(s));
        return s;
      }
    }

    std::optional<std::array<uint16_t, 8>> find_equix_solution(
      const void* challenge,
      const size_t challenge_size
    ) {
      if (challenge == nullptr || challenge_size == 0)
        return std::nullopt;

      equix_ctx* ctx = equix_alloc(EQUIX_CTX_SOLVE);
      if (ctx == nullptr) {
        return std::nullopt;
      }

      equix_solution solution[EQUIX_MAX_SOLS];
      int solution_count = equix_solve(ctx, challenge, challenge_size, solution);

      equix_free(ctx);

      if (solution_count <= 0)
        return std::nullopt;

      return equix_solution_to_array(solution[0]);
    }

    bool verify_equix_solution(
      const void* challenge,
      const size_t challenge_size,
      const std::array<uint16_t, 8> solution
    ) {
      if (challenge == nullptr || challenge_size == 0)
        return false;

      equix_ctx* ctx = equix_alloc(EQUIX_CTX_VERIFY);

      if (ctx == nullptr) {
        return false;
      }

      equix_result result = equix_verify(
        ctx,
        challenge,
        challenge_size,
        reinterpret_cast<const equix_solution*>(solution.data())
      );

      equix_free(ctx);

      return (result == EQUIX_OK);
    }

    uint32_t create_difficulty_scalar(
      const void* challenge,
      const size_t challenge_size,
      const std::array<uint16_t, 8> solution
    ) {
      assert(challenge != nullptr);
      assert(challenge_size != 0);

      const size_t personalization_size = PERSONALIZATION_STRING.size();
      const size_t solution_size = solution.size() * sizeof(uint16_t);

      const uint8_t *solution_bytes = reinterpret_cast<const uint8_t*>(solution.data());

      blake2b_state state;
      blake2b_init(&state, 4);
      blake2b_update(&state, PERSONALIZATION_STRING.data(), personalization_size);
      blake2b_update(&state, static_cast<const uint8_t*>(challenge), challenge_size);
      blake2b_update(&state, solution_bytes, solution_size);

      uint8_t out[4];
      blake2b_final(&state, out, 4);

      uint32_t scalar;
      memcpy_swap32le(&scalar, out, sizeof(scalar));

      return scalar;
    }

    bool check_difficulty(uint32_t scalar, uint32_t difficulty)
    {
      const std::uint64_t product =
        static_cast<std::uint64_t>(scalar) * static_cast<std::uint64_t>(difficulty);

      return product <= std::numeric_limits<std::uint32_t>::max();
    }

    std::array<std::uint8_t, CHALLENGE_SIZE_RPC> create_challenge_rpc(
      const crypto::hash tx_prefix_hash,
      const crypto::hash recent_block_hash,
      const uint32_t nonce
    ) noexcept {
      std::array<std::uint8_t, CHALLENGE_SIZE_RPC> out {};

      memcpy(out.data(), PERSONALIZATION_STRING.data(), PERSONALIZATION_STRING.size());
      memcpy(out.data() + 12, reinterpret_cast<const void*>(&tx_prefix_hash), 32);
      memcpy(out.data() + 44, reinterpret_cast<const void*>(&recent_block_hash), 32);

      const uint32_t n = swap32le(nonce);
      memcpy(out.data() + 76, &n, sizeof(n));

      return out;
    }

    std::array<std::uint8_t, CHALLENGE_SIZE_P2P> create_challenge_p2p(
      const uint64_t power_challenge_nonce,
      const uint64_t power_challenge_nonce_top64,
      const uint32_t nonce
    ) noexcept {
      std::array<std::uint8_t, CHALLENGE_SIZE_P2P> out {};

      memcpy(out.data(), PERSONALIZATION_STRING.data(), PERSONALIZATION_STRING.size());

      const uint128_t nonce_128 =
        (uint128_t(power_challenge_nonce_top64) << 64) | power_challenge_nonce;

      std::array<std::uint8_t, 16> bytes_128;
      boost::multiprecision::export_bits(nonce_128, std::begin(bytes_128), 8, false);

      memcpy(out.data() + 12, bytes_128.data(), bytes_128.size());

      const uint32_t n = swap32le(nonce);
      memcpy(out.data() + 28, &n, sizeof(n));

      return out;
    }

    power_solution solve_rpc(
      const crypto::hash& tx_prefix_hash,
      const crypto::hash& recent_block_hash,
      const uint32_t difficulty
    ) {
      equix_ctx* ctx = equix_alloc(EQUIX_CTX_SOLVE);

      if (ctx == nullptr) {
        throw std::runtime_error("equix_alloc returned nullptr");
      }

      std::array<std::uint8_t, CHALLENGE_SIZE_RPC> challenge =
        create_challenge_rpc(tx_prefix_hash, recent_block_hash, 0);

      equix_solution solutions[EQUIX_MAX_SOLS];
      std::array<uint16_t, 8> solution;

      for (uint32_t nonce = 0;; ++nonce) {
        const uint32_t n = swap32le(nonce);
        memcpy(challenge.data() + 76, &n, sizeof(n));

        const int solution_count = equix_solve(ctx, challenge.data(), challenge.size(), solutions);

        if (solution_count <= 0)
        {
          continue;
        }

        for (int i = 0; i < solution_count; ++i) {
          memcpy(solution.data(), solutions[i].idx, solution.size());
          uint32_t scalar = create_difficulty_scalar(challenge.data(), challenge.size(), solution);

          if (check_difficulty(scalar, difficulty)) {
            power_solution s;
            s.challenge = std::vector(challenge.begin(), challenge.end());
            s.solution = solution;
            s.nonce = nonce;
            equix_free(ctx);
            return s;
          }
        }
      }

      equix_free(ctx);
      throw std::runtime_error("practically unreachable for realistic difficulties");
    }

    power_solution solve_p2p(
      uint64_t power_challenge_nonce,
      uint64_t power_challenge_nonce_top64,
      uint32_t difficulty
    ) {
      // TODO
      power_solution s;
      return s;
    }

    bool verify(
      const void* challenge,
      const size_t challenge_size,
      const uint32_t difficulty,
      const std::array<uint16_t, 8> solution
    ) {
      if (!verify_equix_solution(challenge, challenge_size, solution))
        return false;

      const uint32_t scalar = create_difficulty_scalar(challenge, challenge_size, solution);
      return (check_difficulty(scalar, difficulty));
    }

    bool verify_rpc(
      const crypto::hash& tx_prefix_hash,
      const crypto::hash& recent_block_hash,
      const uint32_t nonce,
      const uint32_t difficulty,
      const std::array<uint16_t, 8> solution
    ) {
      std::array<std::uint8_t, CHALLENGE_SIZE_RPC> challenge = create_challenge_rpc(
        tx_prefix_hash,
        recent_block_hash,
        nonce
      );

      return verify(challenge.data(), challenge.size(), difficulty, solution);
    }

    bool verify_p2p(
      const uint64_t power_challenge_nonce,
      const uint64_t power_challenge_nonce_top64,
      const uint32_t nonce,
      const uint32_t difficulty,
      const std::array<uint16_t, 8> solution
    ) {
      std::array<std::uint8_t, CHALLENGE_SIZE_P2P> challenge = create_challenge_p2p(
        power_challenge_nonce,
        power_challenge_nonce_top64,
        nonce
      );

      return verify(challenge.data(), challenge.size(), difficulty, solution);
    }

  } // namespace power
} // namespace tools

// Copyright (c) 2014-2024, The Monero Project
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
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

//test header
#include "gtest/gtest.h"

//local headers
#include "common/power.cpp"
#include "common/power.h"
#include "string_tools.h"

//third party headers
#include <equix.h>

//standard headers
#include <cstdint>
#include <string_view>

struct test_data {
  std::string_view challenge;
  std::string_view expected_solution;
  int expected_solution_count;
  uint32_t expected_difficulty_scalar;
};

constexpr std::array<test_data, 15> data{{
  {
    "よ、ひさしぶりだね。",
    "546658a95f6466ecc41b24dca5a5e8f5", 3, 609012647
  },
  {
    "👋,🕒👉🕘.",
    "7854ba6c1c9bf7cc9354aed876ce64f4", 3, 1651207227
  },
  {
    "Privacy is necessary for an open society in the electronic age.",
    "7d1467364825e586ae44b9e95ff388f3", 4, 2074493700
  },
  {
    "Privacy is not secrecy.",
    "84033a111b08115b6c70bf8bca6ceb9a", 2, 646700092
  },
  {
    "A private matter is something one doesn't want the whole world to know, ",
    "4c0c432d91278ca49249b76179af2ac8", 2, 3316902313
  },
  {
    "but a secret matter is something one doesn't want anybody to know.",
    "d45afa93b24bddcbf42be882cccd48f0", 2, 2235008675
  },
  {
    "Privacy is the power to selectively reveal oneself to the world.",
    "0380b084f9310287457d038a9e8519ce", 2, 3533046994
  },
  {
    "We must defend our own privacy if we expect to have any.",
    "a330e6561142a57be57513c1095d46ff", 3, 1892198895
  },
  {
    "We must come together and create systems which allow anonymous transactions to take place.",
    "ca1e0362d9252bbb85c62fcdf4ac68f6", 2, 283799637
  },
  {
    "The technologies of the past did not allow for strong privacy, but electronic technologies do.", "3c294b4fdb3454eace4788e45b15c4ea", 1, 3783407380
  },
  {
    "We the Cypherpunks are dedicated to building anonymous systems.",
    "ba09776c7b003279bb1ffe84b4641de9", 1, 1752710302
  },
  {
    "We are defending our privacy with cryptography, ",
    "a455f36d041734a1d477f4c8454f76fc", 1, 1007078876
  },
  {
    "with anonymous mail forwarding systems, ",
    "d61e858ee06e40d3061b68dedf346ae5", 2, 2734745491
  },
  {
    "with digital signatures, ",
    "be227645da4148632d4b64a1d11acfe1", 1, 2211960322
  },
  {
    "and with electronic money.",
    "9439a178579a8ca73654d2afeb447cbc", 3, 283552635
  }
}};

namespace tools
{
  namespace power
  {

    // Test that:
    // - `find_equix_solution` outputs the same bytes as `equix_solve`.
    // - `create_difficulty_scalar` outputs the expected scalar.
    // - `create_difficulty` outputs the expected bool.
    TEST(power, equix_functions)
    {
      equix_ctx* ctx = equix_alloc(EQUIX_CTX_SOLVE);

      for (const auto& t : data)
      {
        const void* challenge = t.challenge.data();
        const size_t size = t.challenge.size();

        std::optional<std::array<uint16_t, 8>> s =
          find_equix_solution(challenge, size);

        equix_solution solution[EQUIX_MAX_SOLS];
        const int count = equix_solve(ctx, challenge, size, solution);
        ASSERT_EQ(count, t.expected_solution_count);

        std::array<uint16_t, 8> s2;
        memcpy(s2.data(), solution[0].idx, sizeof(s2));

        const std::array<uint16_t, 8> s1 = s.value();
        ASSERT_EQ(s1, s2);

        const std::string h1 = epee::string_tools::pod_to_hex(s1);
        const std::string h2 = epee::string_tools::pod_to_hex(s2);
        ASSERT_EQ(h1, t.expected_solution);
        ASSERT_EQ(h2, t.expected_solution);

        ASSERT_EQ(true, verify_equix_solution(challenge, size, s1));
        ASSERT_EQ(true, verify_equix_solution(challenge, size, s2));

        const uint32_t d1 = create_difficulty_scalar(challenge, size, s1);
        const uint32_t d2 = create_difficulty_scalar(challenge, size, s2);
        ASSERT_EQ(d1, t.expected_difficulty_scalar);
        ASSERT_EQ(d2, t.expected_difficulty_scalar);

        const uint32_t last_difficulty_that_passes =
          std::numeric_limits<std::uint32_t>::max() / d1;

        ASSERT_EQ(true, check_difficulty(d1, last_difficulty_that_passes));
        ASSERT_EQ(true, check_difficulty(d2, last_difficulty_that_passes));
        ASSERT_EQ(false, check_difficulty(d1, last_difficulty_that_passes + 1));
        ASSERT_EQ(false, check_difficulty(d2, last_difficulty_that_passes + 1));
      }
    }

    // TODO, check:
    // - create_challenge_{p2p,rpc} creates expected bytes
    // - solve_{p2p,rpc} creates expected solution
    // - verify{_p2p,_rpc} works

  } //namespace power
} // namespace tools

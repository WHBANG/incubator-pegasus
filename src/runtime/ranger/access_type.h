// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

#pragma once

#include <cstdint>

namespace dsn {
namespace ranger {

// ACL type defined in Range service for RPC matching policy
enum class access_type : uint8_t
{
    kInvalid = 0,
    kRead = 1,
    kWrite = 1 << 1,
    kCreate = 1 << 2,
    kDrop = 1 << 3,
    kList = 1 << 4,
    kMetadata = 1 << 5,
    kControl = 1 << 6
};

using act = std::underlying_type<dsn::ranger::access_type>::type;
static access_type access_type_min = kInvalid;
static access_type access_type_max =
    KRead | KWrite | KCreate | KDrop | KList | KMetadata | KControl;

access_type operator|(access_type lhs, access_type rhs);

access_type operator&(access_type lhs, access_type rhs);

access_type &operator|=(access_type &lhs, access_type rhs);

} // namespace ranger
} // namespace dsn

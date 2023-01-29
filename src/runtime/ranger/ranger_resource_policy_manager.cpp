/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include <string>
#include <utility>

#include "ranger_resource_policy_manager.h"
#include "utils/api_utilities.h"
#include "utils/flags.h"
#include "utils/fmt_logging.h"
#include "utils/process_utils.h"

DSN_DEFINE_string("ranger", ranger_service_url, "", "ranger server url");
DSN_DEFINE_string("ranger", ranger_service_name, "", "use policy name");
DSN_DEFINE_string("ranger",
                  ranger_legacy_table_database_mapping_rule,
                  "default",
                  "the policy used by legacy tables after the ACL is enabled");
DSN_DEFINE_bool("ranger", mandatory_enable_acl, "false", "mandatory use ranger policy");

namespace dsn {
namespace ranger {

#define CHECK_DOCUMENT_HAS_MEMBER(document, member)                                                \
    do {                                                                                           \
        if (!document.IsObject() || !document.HasMember(member)) {                                 \
            return dsn::ERR_RANGER_PARSE_ACL;                                                      \
        }                                                                                          \
    } while (0)

#define CHECK_DOCUMENT_HAS_MEMBER_RETURN_VOID(document, member)                                    \
    do {                                                                                           \
        if (!document.IsObject() || !document.HasMember(member)) {                                 \
            return;                                                                                \
        }                                                                                          \
    } while (0)

#define CHECK_DOCUMENT_IS_NON_ARRAY(document)                                                      \
    do {                                                                                           \
        if (!document.IsArray() || document.Size() == 0) {                                         \
            return dsn::ERR_RANGER_PARSE_ACL;                                                      \
        }                                                                                          \
    } while (0)

#define CHECK_DOCUMENT_IS_NON_ARRAY_RETURN_VOID(document)                                          \
    do {                                                                                           \
        if (!document.IsArray() || document.Size() == 0) {                                         \
            return;                                                                                \
        }                                                                                          \
    } while (0)

ranger_resource_policy_manager::ranger_resource_policy_manager()
{
#define ADD_ACL_ITEM(x) _access_type_map.insert(std::pair<std::string, access_type>(#x, x))

    ADD_ACL_ITEM(READ);
    ADD_ACL_ITEM(WRITE);
    ADD_ACL_ITEM(CREATE);
    ADD_ACL_ITEM(DROP);
    ADD_ACL_ITEM(LIST);
    ADD_ACL_ITEM(METADATA);
    ADD_ACL_ITEM(CONTROL);
    ADD_ACL_ITEM(ALL);

    CHECK(_acls.empty(), "ranger acls must be empty.");
    _ranger_service_version = 0;

#undef ADD_ACL_ITEM
}

dsn::error_code ranger_resource_policy_manager::load_ranger_resource_policy()
{
    std::string cmd = "curl " + std::string(FLAGS_ranger_service_url) + "/" +
                      std::string(FLAGS_ranger_service_name);
    std::stringstream resp;

    if (dsn::utils::pipe_execute(cmd.c_str(), resp) != 0) {
        // get policy failed from ranger
        if (FLAGS_mandatory_enable_acl) {
            // clear all policy,todo
            LOG_ERROR_F("get policy failed, clear all policy.");
        } else {
            // use outdated policy
            LOG_WARNING_F("get policy failed, use outdataed policy.");
        }
        return dsn::ERR_RANGER_HTTP_GET;
    }
    return parse(resp.str());
}

dsn::error_code ranger_resource_policy_manager::parse(const std::string &resp)
{
    rapidjson::Document d;
    d.Parse(resp.c_str());
    CHECK_DOCUMENT_HAS_MEMBER(d, "policies");
    // get policy update version
    CHECK_DOCUMENT_HAS_MEMBER(d, "policyVersion");
    int ranger_service_version = d["policyVersion"].GetInt();

    if (_ranger_service_version == ranger_service_version) {
        LOG_INFO_F("ranger service version: {} VS {}, no need to update policy.",
                   _ranger_service_version,
                   ranger_service_version);
        return dsn::ERR_RANGER_POLICIES_NO_NEED_UPDATE;
    }
    if (_ranger_service_version == 0) {
        _ranger_service_version = ranger_service_version;
    }
    _acls.clear();
    ranger_resource_policy default_acl;
    ranger_resource_policy::default_database_resource_builder(default_acl);
    std::vector<ranger_resource_policy> default_resource_policy{default_acl};
    _acls.insert(std::pair<std::string, std::vector<ranger_resource_policy>>(
        enum_to_string(DATABASE), default_resource_policy));
    const rapidjson::Value &policies = d["policies"];

    CHECK_DOCUMENT_IS_NON_ARRAY(policies);
    for (const auto &p : policies.GetArray()) {
        CHECK_DOCUMENT_HAS_MEMBER(p, "isEnabled");
        CHECK_DOCUMENT_HAS_MEMBER(p, "resources");
        // 2. only parse 'isEnabled' policy
        if (p["isEnabled"].IsBool() && p["isEnabled"].GetBool()) {
            // 1. parse resource type
            std::map<std::string, std::set<std::string>> type_map;

            for (const auto &t : p["resources"].GetObject()) {
                std::set<std::string> values;
                for (const auto &v : (t.value)["values"].GetArray()) {
                    values.insert(v.GetString());
                }
                type_map.insert(
                    std::pair<std::string, std::set<std::string>>(t.name.GetString(), values));
            }

            ranger_resource_policy acl;
            if (type_map.size() == 1) {
                if (type_map.find("global") != type_map.end()) {
                    acl._global_values = type_map["global"];
                    resource_policy_constructor(resource_type::GLOBAL, p, acl);
                } else if (type_map.find("database") != type_map.end()) {
                    acl._database_values = type_map["database"];
                    resource_policy_constructor(resource_type::DATABASE, p, acl);
                } else {
                    return dsn::ERR_RANGER_PARSE_ACL;
                }
            } else if (type_map.size() == 2 && type_map.find("database") != type_map.end() &&
                       type_map.find("table") != type_map.end()) {
                acl._database_values = type_map["database"];
                acl._table_values = type_map["table"];
                resource_policy_constructor(resource_type::DATABASE_TABLE, p, acl);
            } else {
                return dsn::ERR_RANGER_PARSE_ACL;
            }
        }
    }
    return dsn::ERR_OK;
}

void ranger_resource_policy_manager::resource_policy_constructor(resource_type type,
                                                                 const rapidjson::Value &d,
                                                                 ranger_resource_policy &acl)
{
    CHECK(
        resource_type::UNKNOWN != type, "resouce type is unknown, type = {}", enum_to_string(type));
    CHECK_DOCUMENT_HAS_MEMBER_RETURN_VOID(d, "name");
    acl._resource_name = d["name"].GetString();
    for (const auto &policy : ranger_resource_policy::_policy_item_list) {
        if (policy == "policyItems") {
            policy_setter(acl._policies.allow_policy, d["policyItems"]);
        } else if (policy == "denyPolicyItems") {
            policy_setter(acl._policies.deny_policy, d["denyPolicyItems"]);
        } else if (policy == "allowExceptions") {
            policy_setter(acl._policies.allow_policy_exclude, d["allowExceptions"]);
        } else {
            policy_setter(acl._policies.deny_policy_exclude, d["denyExceptions"]);
        }
    }
    if (_acls.find(enum_to_string(type)) == _acls.end()) {
        _acls.insert(std::pair<std::string, std::vector<ranger_resource_policy>>(
            enum_to_string(type), std::vector<ranger_resource_policy>{acl}));
    } else {
        _acls[enum_to_string(type)].emplace_back(acl);
    }
}

void ranger_resource_policy_manager::policy_setter(std::vector<policy_item> &policy_list,
                                                   const rapidjson::Value &d)
{
    CHECK(policy_list.empty(), "ranger policy list must be empty.");
    CHECK_DOCUMENT_IS_NON_ARRAY_RETURN_VOID(d);
    for (auto &item : d.GetArray()) {
        CHECK_DOCUMENT_HAS_MEMBER_RETURN_VOID(item, "accesses");
        CHECK_DOCUMENT_HAS_MEMBER_RETURN_VOID(item, "users");
        CHECK_DOCUMENT_HAS_MEMBER_RETURN_VOID(item, "groups");
        CHECK_DOCUMENT_HAS_MEMBER_RETURN_VOID(item, "roles");
        policy_item it;
        for (const auto &access : item["accesses"].GetArray()) {
            if (access["isAllowed"].GetBool()) {
                std::string str_type = access["type"].GetString();
                std::transform(str_type.begin(), str_type.end(), str_type.begin(), toupper);
                access_type type = _access_type_map[str_type];
                it.accesses.insert(type);
            }
        }
        for (const auto &user : item["users"].GetArray()) {
            it.users.insert(user.GetString());
        }
        for (const auto &group : item["groups"].GetArray()) {
            it.groups.insert(group.GetString());
        }
        for (const auto &role : item["roles"].GetArray()) {
            it.roles.insert(role.GetString());
        }
        policy_list.emplace_back(it);
    }
}

resource_acls_type ranger_resource_policy_manager::get_acls() { return _acls; }

#undef CHECK_DOCUMENT_HAS_MEMBER
#undef CHECK_DOCUMENT_HAS_MEMBER_RETURN_VOID
#undef CHECK_DOCUMENT_IS_NON_ARRAY
#undef CHECK_DOCUMENT_IS_NON_ARRAY_RETURN_VOID
} // namespace ranger
} // namespace dsn

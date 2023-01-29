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

#include <memory>
#include <string>
#include <utility>

#include "common/replication.codes.h"
#include "common/replica_envs.h"
#include "ranger_resource_policy_manager.h"
#include "runtime/task/async_calls.h"
#include "utils/api_utilities.h"
#include "utils/flags.h"
#include "utils/fmt_logging.h"
#include "utils/process_utils.h"

namespace dsn {
namespace ranger {

DSN_DEFINE_string(ranger, ranger_service_url, "", "ranger server url");
DSN_DEFINE_string(ranger, ranger_service_name, "", "use policy name");
DSN_DEFINE_string(ranger,
                  ranger_legacy_table_database_mapping_rule,
                  "default",
                  "the policy used by legacy tables after the ACL is enabled");
DSN_DEFINE_bool(ranger, mandatory_enable_acl, "false", "mandatory use ranger policy");

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

ranger_resource_policy_manager::ranger_resource_policy_manager(
    dsn::replication::meta_service *meta_svc, const std::string &ranger_policy_meta_root)
    : _ranger_policy_meta_root(ranger_policy_meta_root),
      _load_ranger_policy_retry_delay_ms(10000),
      _meta_svc(meta_svc)
{
    // RESOURCE_TYPE::GLOBAL - metadata
    register_rpc_match_acl(_rpc_match_global_acl, "RPC_CM_LIST_NODES", access_type::METADATA);
    register_rpc_match_acl(_rpc_match_global_acl, "RPC_CM_CLUSTER_INFO", access_type::METADATA);
    register_rpc_match_acl(_rpc_match_global_acl, "RPC_CM_LIST_APPS", access_type::METADATA);
    register_rpc_match_acl(_rpc_match_global_acl, "RPC_QUERY_DISK_INFO", access_type::METADATA);
    // RESOURCE_TYPE::GLOBAL - control
    register_rpc_match_acl(_rpc_match_global_acl, "RPC_HTTP_SERVICE", access_type::CONTROL);
    register_rpc_match_acl(_rpc_match_global_acl, "RPC_CM_CONTROL_META", access_type::CONTROL);
    register_rpc_match_acl(_rpc_match_global_acl, "RPC_CM_START_RECOVERY", access_type::CONTROL);
    register_rpc_match_acl(_rpc_match_global_acl, "RPC_REPLICA_DISK_MIGRATE", access_type::CONTROL);
    register_rpc_match_acl(_rpc_match_global_acl, "RPC_ADD_NEW_DISK", access_type::CONTROL);
    register_rpc_match_acl(_rpc_match_global_acl, "RPC_DETECT_HOTKEY", access_type::CONTROL);
    register_rpc_match_acl(_rpc_match_global_acl, "RPC_CLI_CLI_CALL_ACK", access_type::CONTROL);
    // RESOURCE_TYPE::DATABASE - list
    register_rpc_match_acl(_rpc_match_database_acl, "RPC_CM_LIST_APPS", access_type::LIST);
    // RESOURCE_TYPE::DATABASE - create
    register_rpc_match_acl(_rpc_match_database_acl, "RPC_CM_CREATE_APP", access_type::CREATE);
    // RESOURCE_TYPE::DATABASE - drop
    register_rpc_match_acl(_rpc_match_database_acl, "RPC_CM_DROP_APP", access_type::DROP);
    register_rpc_match_acl(_rpc_match_database_acl, "RPC_CM_RECALL_APP", access_type::DROP);
    // RESOURCE_TYPE::DATABASE - metadata
    register_rpc_match_acl(
        _rpc_match_database_acl, "RPC_CM_QUERY_BACKUP_STATUS", access_type::METADATA);
    register_rpc_match_acl(
        _rpc_match_database_acl, "RPC_CM_QUERY_RESTORE_STATUS", access_type::METADATA);
    register_rpc_match_acl(
        _rpc_match_database_acl, "RPC_CM_QUERY_DUPLICATION", access_type::METADATA);
    register_rpc_match_acl(
        _rpc_match_database_acl, "RPC_CM_QUERY_PARTITION_SPLIT", access_type::METADATA);
    register_rpc_match_acl(
        _rpc_match_database_acl, "RPC_CM_QUERY_BULK_LOAD_STATUS", access_type::METADATA);
    register_rpc_match_acl(
        _rpc_match_database_acl, "RPC_CM_QUERY_MANUAL_COMPACT_STATUS", access_type::METADATA);
    register_rpc_match_acl(
        _rpc_match_database_acl, "RPC_CM_GET_MAX_REPLICA_COUNT", access_type::METADATA);
    // RESOURCE_TYPE::DATABASE - control
    register_rpc_match_acl(
        _rpc_match_database_acl, "RPC_CM_START_BACKUP_APP", access_type::CONTROL);
    register_rpc_match_acl(_rpc_match_database_acl, "RPC_CM_START_RESTORE", access_type::CONTROL);
    register_rpc_match_acl(
        _rpc_match_database_acl, "RPC_CM_PROPOSE_BALANCER", access_type::CONTROL);
    register_rpc_match_acl(_rpc_match_database_acl, "RPC_CM_ADD_DUPLICATION", access_type::CONTROL);
    register_rpc_match_acl(
        _rpc_match_database_acl, "RPC_CM_MODIFY_DUPLICATION", access_type::CONTROL);
    register_rpc_match_acl(_rpc_match_database_acl, "RPC_CM_UPDATE_APP_ENV", access_type::CONTROL);
    register_rpc_match_acl(_rpc_match_database_acl, "RPC_CM_DDD_DIAGNOSE", access_type::CONTROL);
    register_rpc_match_acl(
        _rpc_match_database_acl, "RPC_CM_START_PARTITION_SPLIT", access_type::CONTROL);
    register_rpc_match_acl(
        _rpc_match_database_acl, "RPC_CM_CONTROL_PARTITION_SPLIT", access_type::CONTROL);
    register_rpc_match_acl(_rpc_match_database_acl, "RPC_CM_START_BULK_LOAD", access_type::CONTROL);
    register_rpc_match_acl(
        _rpc_match_database_acl, "RPC_CM_CONTROL_BULK_LOAD", access_type::CONTROL);
    register_rpc_match_acl(_rpc_match_database_acl, "RPC_CM_CLEAR_BULK_LOAD", access_type::CONTROL);
    register_rpc_match_acl(
        _rpc_match_database_acl, "RPC_CM_START_MANUAL_COMPACT", access_type::CONTROL);
    register_rpc_match_acl(
        _rpc_match_database_acl, "RPC_CM_SET_MAX_REPLICA_COUNT", access_type::CONTROL);
    register_rpc_match_acl(_rpc_match_database_acl, "RPC_CM_RENAME_APP", access_type::CONTROL);

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

void ranger_resource_policy_manager::register_rpc_match_acl(rpc_match_acl_type &resource,
                                                            const std::string &rpc_code,
                                                            const access_type &type)
{
    auto code = task_code::try_get(rpc_code, TASK_CODE_INVALID);
    CHECK_NE_MSG(code,
                 TASK_CODE_INVALID,
                 "invalid task code({}) in rpc_code_white_list of security section",
                 rpc_code);

    resource.insert(std::make_pair(code, type));
}

bool ranger_resource_policy_manager::allowed(const int rpc_code,
                                             const std::string &user_name,
                                             const std::string &database_name)
{
    {
        utils::auto_read_lock l(_global_policies_lock);
        if (_rpc_match_global_acl.find(rpc_code) != _rpc_match_global_acl.end()) {
            for (auto &item : _global_policies) {
                const access_type &type = _rpc_match_global_acl[rpc_code];
                if (item._policies.allowed(user_name, type)) {
                    return true;
                }
            }
            if (rpc_code != RPC_CM_LIST_APPS.code()) {
                return false;
            }
        }
    }
    {
        utils::auto_read_lock l(_database_policies_lock);
        if (_rpc_match_database_acl.find(rpc_code) != _rpc_match_database_acl.end()) {
            for (auto &item : _database_policies) {
                const access_type &type = _rpc_match_database_acl[rpc_code];
                if (item._policies.allowed(user_name, type)) {
                    if ("" == database_name &&
                        item._database_values.find("*") != item._database_values.end()) {
                        return true;
                    }
                    if (item._database_values.find(database_name) != item._database_values.end()) {
                        return true;
                    }
                }
            }
            return false;
        }
    }
    // old env deal way: todo
    return false;
}

void ranger_resource_policy_manager::update()
{
    dsn::error_code err_code = load_ranger_resource_policy();
    if (err_code == dsn::ERR_RANGER_POLICIES_NO_NEED_UPDATE) {
        LOG_DEBUG_F("No need to update ACLs policies with error code = {}", err_code);
        return;
    }
    if (err_code != dsn::ERR_OK) {
        LOG_WARNING_F("get ranger policy failed, {}.", err_code);
    } else {
        LOG_DEBUG_F("get ranger policy success, {}.", err_code);
        dsn::task_ptr after_create_ranger_policy_meta_root = dsn::tasking::create_task(
            LPC_CM_GET_RANGER_POLICY, &_tracker, [this]() { start_sync_ranger_policies(); });
        create_ranger_policy_root(after_create_ranger_policy_meta_root);
    }
}

void ranger_resource_policy_manager::create_ranger_policy_root(dsn::task_ptr callback)
{
    LOG_DEBUG_F("create ranger policy meta root({}) on remote_storage",
                _ranger_policy_meta_root.c_str());
    _meta_svc->get_remote_storage()->create_node(
        _ranger_policy_meta_root, LPC_CM_GET_RANGER_POLICY, [this, callback](dsn::error_code err) {
            if (err == dsn::ERR_OK || err == ERR_NODE_ALREADY_EXIST) {
                LOG_DEBUG_F("create ranger policy meta root({}) succeed, with err ({})",
                            _ranger_policy_meta_root.c_str(),
                            err.to_string());
                callback->enqueue();
            } else if (err == dsn::ERR_TIMEOUT) {
                LOG_ERROR_F("create ranger policy meta root({}) timeout, try it later",
                            _ranger_policy_meta_root.c_str());
                dsn::tasking::enqueue(
                    LPC_CM_GET_RANGER_POLICY,
                    &_tracker,
                    std::bind(
                        &ranger_resource_policy_manager::create_ranger_policy_root, this, callback),
                    0,
                    _load_ranger_policy_retry_delay_ms);
            } else {
                CHECK(false, "we can't handle this error({}) right now", err.to_string());
            }
        });
}

void ranger_resource_policy_manager::start_sync_ranger_policies()
{
    LOG_DEBUG_F("start to sync rannger policies to remote storage");
    dsn::error_code err = sync_policies_to_remote_storage();
    if (err == dsn::ERR_OK) {
        LOG_DEBUG_F("sync ranger policies to remote storage succeed, with err ({})",
                    err.to_string());
        err = sync_policies_to_cache();
        if (err == dsn::ERR_OK) {
            LOG_DEBUG_F("updata rannger policies to cahce, err with {}", err.to_string());
            err = sync_policies_to_apps();
            if (err == dsn::ERR_OK) {
                LOG_DEBUG_F("updata rannger policies to apps, err with {}", err.to_string());
            }
        }
    } else {
        CHECK(false,
              "sync policies to cache error({}), we can't handle this right now",
              err.to_string());
    }
}

dsn::error_code ranger_resource_policy_manager::sync_policies_to_remote_storage()
{
    dsn::error_code err;
    dsn::blob value = json::json_forwarder<resource_acls_type>::encode(_acls);
    _meta_svc->get_remote_storage()->set_data(
        _ranger_policy_meta_root, value, LPC_CM_GET_RANGER_POLICY, [this, &err](dsn::error_code e) {
            err = e;
            if (e == ERR_OK) {
                LOG_DEBUG_F("updata rannger policies to remote storage succeed, err with {}",
                            err.to_string());
            } else if (e == ERR_TIMEOUT) {
                LOG_ERROR_F(
                    "updata rannger policies to remote storage failed, err with = {}, retry "
                    "after %" PRId64 "(ms)",
                    err.to_string(),
                    _load_ranger_policy_retry_delay_ms.count());
                dsn::tasking::enqueue(
                    LPC_CM_GET_RANGER_POLICY,
                    &_tracker,
                    std::bind(&ranger_resource_policy_manager::sync_policies_to_remote_storage,
                              this),
                    0,
                    _load_ranger_policy_retry_delay_ms);
            } else {
                CHECK(false,
                      "we can't handle this when update ranger policy, err with {}",
                      err.to_string());
            }
        });
    return err;
}

dsn::error_code ranger_resource_policy_manager::sync_policies_to_cache()
{
    {
        utils::auto_write_lock l(_global_policies_lock);
        _global_policies.clear();
        _global_policies.swap(_acls[enum_to_string(resource_type::GLOBAL)]);
        dsn::blob value =
            json::json_forwarder<ranger_resource_policies_set>::encode(_global_policies);
        LOG_DEBUG_F("update global_policies cahce, value = {}", value.to_string());
    }
    {
        utils::auto_write_lock l(_database_policies_lock);
        _database_policies.clear();
        _database_policies.swap(_acls[enum_to_string(resource_type::DATABASE)]);
        dsn::blob value =
            json::json_forwarder<ranger_resource_policies_set>::encode(_database_policies);
        LOG_DEBUG_F("update database_policies cahce, value = {}", value.to_string());
    }
    return dsn::ERR_OK;
}

dsn::error_code ranger_resource_policy_manager::sync_policies_to_apps()
{
    if (_acls.count(enum_to_string(resource_type::DATABASE_TABLE)) == 0) {
        LOG_DEBUG_F("database_table is null");
        return dsn::ERR_OK;
    }
    auto table_policies = _acls[enum_to_string(resource_type::DATABASE_TABLE)];

    dsn::blob value = json::json_forwarder<ranger_resource_policies_set>::encode(table_policies);
    LOG_DEBUG_F("table policy value = {}", value.to_string());

    dsn::replication::configuration_list_apps_response list_apps_resp;
    dsn::replication::configuration_list_apps_request list_apps_req;
    list_apps_req.status = dsn::app_status::AS_AVAILABLE;

    _meta_svc->get_server_state()->list_apps(list_apps_req, list_apps_resp);

    if (list_apps_resp.err != dsn::ERR_OK) {
        return list_apps_resp.err;
    }
    std::vector<::dsn::app_info> &apps = list_apps_resp.infos;

    for (const auto &app : apps) {
        std::vector<std::string> lv;
        ::dsn::utils::split_args(app.app_name.c_str(), lv, '.');
        std::string app_name_prefix_match = "";
        std::string app_name = "";
        if (lv.size() == 1) {
            app_name_prefix_match = "*";
            app_name = lv[0];
        } else if (lv.size() == 2) {
            app_name_prefix_match = lv[0];
            app_name = lv[1];
        } else {
            LOG_ERROR_F("update app() envs failed with error_code(ERR_INVALID_APP_NAME)",
                        app.app_name);
            continue;
        }
        auto req = dsn::make_unique<dsn::replication::configuration_update_app_env_request>();
        req->__set_app_name(app.app_name);
        req->__set_keys(std::vector<std::string>{
            dsn::replication::replica_envs::REPLICA_ACCESS_CONTROLLER_RANGER_POLICIES});
        bool has_match_policy = false;
        for (const auto &policy : table_policies) {
            // a policy was matched
            if ((std::find(policy._database_values.begin(),
                           policy._database_values.end(),
                           app_name_prefix_match) == policy._database_values.end())) {
                continue;
            }
            if ((std::find(policy._table_values.begin(), policy._table_values.end(), "*") !=
                 policy._table_values.end()) ||
                (std::find(policy._table_values.begin(), policy._table_values.end(), app_name) !=
                 policy._table_values.end())) {
                has_match_policy = true;
                req->__set_op(dsn::replication::app_env_operation::type::APP_ENV_OP_SET);
                req->__set_values(std::vector<std::string>{
                    json::json_forwarder<policy_priority_level>::encode(policy._policies)
                        .to_string()});
                dsn::replication::update_app_env_rpc rpc(std::move(req), LPC_CM_GET_RANGER_POLICY);
                _meta_svc->get_server_state()->set_app_envs(rpc);
                auto rpc_resp = rpc.response();
                if (rpc_resp.err != dsn::ERR_OK) {
                    return rpc_resp.err;
                }
                break;
            }
        }
        // no match policy, clear app ranger policy
        if (!has_match_policy) {
            req->__set_op(dsn::replication::app_env_operation::type::APP_ENV_OP_DEL);
            dsn::replication::update_app_env_rpc rpc(std::move(req), LPC_CM_GET_RANGER_POLICY);
            _meta_svc->get_server_state()->del_app_envs(rpc);
            auto rpc_resp = rpc.response();
            if (rpc_resp.err != dsn::ERR_OK) {
                return rpc_resp.err;
            }
        }
    }
    return dsn::ERR_OK;
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
        LOG_DEBUG_F("ranger service version: {} VS {}, no need to update policy.",
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
    ranger_resource_policies_set default_resource_policy{default_acl};
    _acls.insert(std::pair<std::string, ranger_resource_policies_set>(enum_to_string(DATABASE),
                                                                      default_resource_policy));
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
        _acls.insert(std::pair<std::string, ranger_resource_policies_set>(
            enum_to_string(type), ranger_resource_policies_set{acl}));
    } else {
        _acls[enum_to_string(type)].emplace(acl);
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

#undef CHECK_DOCUMENT_HAS_MEMBER
#undef CHECK_DOCUMENT_HAS_MEMBER_RETURN_VOID
#undef CHECK_DOCUMENT_IS_NON_ARRAY
#undef CHECK_DOCUMENT_IS_NON_ARRAY_RETURN_VOID

} // namespace ranger
} // namespace dsn

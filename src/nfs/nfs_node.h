/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Microsoft Corporation
 *
 * -=- Robust Distributed System Nucleus (rDSN) -=-
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#pragma once

#include <memory>
#include <string>

#include "aio/aio_task.h"
#include "nfs_code_definition.h"
#include "nfs_types.h"
#include "runtime/serverlet.h"
#include "utils/utils.h"
#include "utils/binary_reader.h"
#include "utils/binary_writer.h"

namespace dsn {

struct remote_copy_request
{
    dsn::rpc_address source;
    std::string source_disk_tag;
    std::string source_dir;
    std::vector<std::string> files;
    std::string dest_disk_tag;
    std::string dest_dir;
    bool overwrite;
    bool high_priority;
    dsn::gpid pid;
};

class nfs_node
{
public:
    static std::unique_ptr<nfs_node> create();

public:
    aio_task_ptr copy_remote_directory(const rpc_address &remote,
                                       const std::string &source_disk_tag,
                                       const std::string &source_dir,
                                       const std::string &dest_disk_tag,
                                       const std::string &dest_dir,
                                       const dsn::gpid &pid,
                                       bool overwrite,
                                       bool high_priority,
                                       task_code callback_code,
                                       task_tracker *tracker,
                                       aio_handler &&callback,
                                       int hash = 0);
    aio_task_ptr copy_remote_files(const rpc_address &remote,
                                   const std::string &source_disk_tag,
                                   const std::string &source_dir,
                                   const std::vector<std::string> &files, // empty for all
                                   const std::string &dest_disk_tag,
                                   const std::string &dest_dir,
                                   const dsn::gpid &pid,
                                   bool overwrite,
                                   bool high_priority,
                                   task_code callback_code,
                                   task_tracker *tracker,
                                   aio_handler &&callback,
                                   int hash = 0);

    aio_task_ptr copy_remote_files(std::shared_ptr<remote_copy_request> &request,
                                   task_code callback_code,
                                   task_tracker *tracker,
                                   aio_handler &&callback,
                                   int hash = 0);

    nfs_node() {}
    virtual ~nfs_node() {}
    virtual error_code start() = 0;
    virtual error_code stop() = 0;
    virtual void on_copy(const ::dsn::service::copy_request &request,
                         ::dsn::rpc_replier<::dsn::service::copy_response> &reply) = 0;
    virtual void
    on_get_file_size_copy(const ::dsn::service::get_file_size_request &request,
                          ::dsn::rpc_replier<::dsn::service::get_file_size_response> &reply) = 0;
    virtual void register_async_rpc_handler_for_test() = 0;

protected:
    virtual void call(std::shared_ptr<remote_copy_request> rci, aio_task *callback) = 0;
};
}

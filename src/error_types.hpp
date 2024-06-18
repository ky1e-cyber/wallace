#pragma once

#include <expected>
#include <string>

enum class error_t { fatal, non_fatal };

struct fail_t {
    error_t err_type;
    std::string msg;
};

fail_t fail_combine(fail_t& f1, fail_t& f2);

template <typename T>
using try_t = std::expected<T, fail_t>;

using try_op_t = try_t<void>;

try_op_t try_op_combine(try_op_t&& res1, try_op_t&& res2);

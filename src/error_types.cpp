#include "error_types.hpp"

fail_t fail_combine(fail_t& f1, fail_t& f2) {
    return {.err_type =
                (f1.err_type == error_t::fatal or f2.err_type == error_t::fatal)
                    ? error_t::fatal
                    : error_t::non_fatal,
            .msg = f1.msg.append(f2.msg)};
    // TODO add delimiter and nicer formatting
}

try_op_t try_op_combine(try_op_t&& res1, try_op_t&& res2) {
    if (res1.has_value()) {
        return res2;
    } else {
        return res2.has_value()
                   ? res1
                   : std::unexpected(fail_combine(res1.error(), res2.error()));
    }
}

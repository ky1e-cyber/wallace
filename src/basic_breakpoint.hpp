#pragma once

#include <cinttypes>

struct basic_breakpoint {
    uintptr_t addr;
    uint32_t saved_data;
    bool enabled;
};

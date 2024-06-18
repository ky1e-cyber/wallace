#pragma once

#include <mach/mach.h>
#include <expected>
#include <functional>
#include <vector>

#include "basic_breakpoint.hpp"
#include "common.hpp"
#include "error_types.hpp"

class aarch64_darwin_process : private non_copyable {
   public:
    pid_t get_pid();

    static try_t<aarch64_darwin_process> spawn(
        const std::string& exec_path,
        const std::vector<std::string>& args);

    try_op_t continue_execution();
    try_op_t step_execution();
    try_t<basic_breakpoint> set_breakpoint(uintptr_t addr);
    try_t<basic_breakpoint> disable_breakpoint(basic_breakpoint brk);
    try_t<basic_breakpoint> enable_breakpoint(basic_breakpoint brk);

    aarch64_darwin_process(aarch64_darwin_process&& moved);
    ~aarch64_darwin_process();

   private:
    pid_t pid_;
    mach_port_t mach_port_;

    aarch64_darwin_process(pid_t pid);

    try_op_t set_vm_protection(mach_vm_address_t addr,
                               mach_vm_size_t size,
                               vm_prot_t protection,
                               bool is_fatal);
    try_op_t read_vm_address(mach_vm_address_t addr,
                             mach_vm_size_t size,
                             mach_vm_address_t dst,
                             bool is_fatal);
    try_op_t write_vm_address(mach_vm_address_t addr,
                              vm_offset_t source,
                              mach_vm_size_t size,
                              bool is_fatal);

    /*
        sets guard between vm_op() like that:

            *set protection to read and write*
                            |
                            v
                        *do vm_op*
                            |
                            v
                    *set protection back*

    */
    try_op_t vm_protection_guard(
        std::function<try_op_t(mach_vm_address_t, mach_vm_size_t)> vm_op,
        mach_vm_address_t addr,
        mach_vm_size_t size,
        vm_prot_t original_prot);
};

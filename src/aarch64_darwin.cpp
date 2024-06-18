#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <spawn.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <csignal>
#include <cstring>
#include <vector>

#include "aarch64_darwin.hpp"
#include "error_types.hpp"

#ifndef _POSIX_SPAWN_DISABLE_ASLR
#define _POSIX_SPAWN_DISABLE_ASLR 0x0100
#endif

static const uint32_t BRK0_CODE = 0xd4200000;

static std::vector<const char*> nullterm_args(
    const std::string path,
    const std::vector<std::string>& args) {
    std::vector<const char*> cargs;
    cargs.reserve(args.size() + 2);

    cargs.push_back(path.c_str());

    for (size_t i = 0; i < args.size(); i++) {
        cargs.push_back(args[i].c_str());
    }
    cargs.push_back(nullptr);

    return cargs;
}

[[noreturn]]
static void darwin_exec(const std::string& path,
                        const std::vector<std::string>& args) {
    pid_t pid;
    posix_spawnattr_t attr;

    short flag = POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK |
                 POSIX_SPAWN_SETEXEC | _POSIX_SPAWN_DISABLE_ASLR;

    sigset_t no_signals;
    sigset_t all_signals;
    sigemptyset(&no_signals);
    sigfillset(&all_signals);

    if (posix_spawnattr_init(&attr) != 0 or
        posix_spawnattr_setsigmask(&attr, &no_signals) != 0 or
        posix_spawnattr_setsigdefault(&attr, &all_signals) != 0 or
        posix_spawnattr_setflags(&attr, flag) != 0) {
        //
        posix_spawnattr_destroy(&attr);
        fprintf(stderr, "ERROR: Unable to init spawn attributes\n");
        exit(1);
    }

    errno = 0;
    if (ptrace(PT_TRACE_ME, 0, nullptr, 0) == -1) {
        fprintf(stderr, "ERROR: Unable to send PT_TRACE_ME via ptrace()\n");
        exit(1);
    }

    // spawns <defunct> if non valid path provided (SOMEHOW)
    // probably should check path before that
    // although it won't be able to open port anyway in that case
    int res =
        posix_spawnp(&pid, path.c_str(), nullptr, &attr,
                     (char* const*)nullterm_args(path, args).data(), nullptr);

    posix_spawnattr_destroy(&attr);

    if (res != 0) {
        fprintf(stderr, "ERROR: Unable to spawn process\n");
    } else {
        fprintf(stderr, "WELP THATS STRANGE");
    }

    exit(1);
}

pid_t aarch64_darwin_process::get_pid() {
    return this->pid_;
}

try_t<aarch64_darwin_process> aarch64_darwin_process::spawn(
    const std::string& path,
    const std::vector<std::string>& args) {
    errno = 0;

    pid_t pid = fork();

    if (pid == -1) {
        return std::unexpected(fail_t{.err_type = error_t::non_fatal,
                                      .msg = "failed to fork() process"});
    } else if (pid == 0) {
        darwin_exec(path, args);
    } else {
        errno = 0;
        int status;
        if (waitpid(pid, &status, 0) == -1) {
            std::string err = "waitpid() failed due to: ";
            err.append(strerror(errno));
            return std::unexpected(
                fail_t{.err_type = error_t::fatal, .msg = err});
        };

        if (not(WIFSTOPPED(status) and WSTOPSIG(status) == SIGTRAP)) {
            return std::unexpected(
                fail_t{.err_type = error_t::fatal,
                       .msg = "Process wasn't stopped with SIGTRAP"});
        }

        aarch64_darwin_process process{pid};

        mach_port_t port;
        if (task_for_pid(mach_task_self(), pid, &port) != KERN_SUCCESS)
            return std::unexpected(fail_t{.err_type = error_t::fatal,
                                          .msg = "Unable to create Mach port"});

        process.mach_port_ = port;
        return process;
    }
}

try_op_t aarch64_darwin_process::continue_execution() {
    errno = 0;
    if (ptrace(PT_CONTINUE, pid_, (caddr_t)1, 0) == -1)
        return std::unexpected(
            fail_t{.err_type = error_t::non_fatal, .msg = strerror(errno)});
    return {};
}

try_op_t aarch64_darwin_process::step_execution() {
    errno = 0;
    if (ptrace(PT_STEP, pid_, (caddr_t)1, 0) == -1)
        return std::unexpected(
            fail_t{.err_type = error_t::fatal, .msg = strerror(errno)});
    int status;
    waitpid(pid_, &status, 0);
    return {};
}

try_t<basic_breakpoint> aarch64_darwin_process::set_breakpoint(uintptr_t addr) {
    //
    basic_breakpoint brk;
    auto op = [&brk, this](mach_vm_address_t addr, mach_vm_size_t size) {
        return this
            ->read_vm_address(addr, size, (mach_vm_address_t)&brk.saved_data,
                              false)
            .and_then([addr, size, this]() {
                return this->write_vm_address(addr, (vm_offset_t)&BRK0_CODE,
                                              size, false);
            });
    };

    auto res = vm_protection_guard(op, (mach_vm_address_t)addr, 4,
                                   VM_PROT_EXECUTE | VM_PROT_READ);

    if (not res.has_value())
        return std::unexpected(res.error());

    return brk;
}

try_t<basic_breakpoint> aarch64_darwin_process::disable_breakpoint(
    basic_breakpoint brk) {
    if (not brk.enabled)
        return brk;

    auto op = [&brk, this](mach_vm_address_t addr, mach_vm_size_t size) {
        return write_vm_address(addr, (vm_offset_t)&brk.saved_data, size,
                                false);
    };

    auto res = vm_protection_guard(op, (mach_vm_address_t)brk.addr, 4,
                                   VM_PROT_EXECUTE | VM_PROT_READ);

    if (not res.has_value())
        return std::unexpected(res.error());

    return basic_breakpoint{
        .addr = brk.addr, .saved_data = brk.saved_data, .enabled = false};
}

try_t<basic_breakpoint> aarch64_darwin_process::enable_breakpoint(
    basic_breakpoint brk) {
    if (brk.enabled)
        return brk;

    auto op = [this](mach_vm_address_t addr, mach_vm_size_t size) {
        return write_vm_address(addr, (vm_offset_t)&BRK0_CODE, size, false);
    };

    auto res = vm_protection_guard(op, (mach_vm_address_t)brk.addr, 4,
                                   VM_PROT_EXECUTE | VM_PROT_READ);

    if (not res.has_value())
        return std::unexpected(res.error());

    return basic_breakpoint{
        .addr = brk.addr, .saved_data = brk.saved_data, .enabled = true};
}

aarch64_darwin_process::aarch64_darwin_process(aarch64_darwin_process&& moved)
    : aarch64_darwin_process(moved.pid_) {
    this->mach_port_ = moved.mach_port_;
    moved.pid_ = -1;
    moved.mach_port_ = 0;
}

aarch64_darwin_process::~aarch64_darwin_process() {
    ptrace(PT_KILL, pid_, (caddr_t)1, 0);
}

// private

aarch64_darwin_process::aarch64_darwin_process(pid_t pid) : pid_{pid} {}

try_op_t aarch64_darwin_process::set_vm_protection(mach_vm_address_t addr,
                                                   mach_vm_size_t size,
                                                   vm_prot_t protection,
                                                   bool is_fatal) {
    if (mach_vm_protect(mach_port_, addr, size, (boolean_t)FALSE, protection) !=
        KERN_SUCCESS)
        return std::unexpected(
            fail_t{.err_type = is_fatal ? error_t::fatal : error_t::non_fatal,
                   .msg = "failed to set vm protection"});

    return {};
}

try_op_t aarch64_darwin_process::read_vm_address(mach_vm_address_t addr,
                                                 mach_vm_size_t size,
                                                 mach_vm_address_t dst,
                                                 bool is_fatal) {
    mach_vm_size_t size_dst;
    if (mach_vm_read_overwrite(mach_port_, (mach_vm_address_t)addr, size, dst,
                               &size_dst) != KERN_SUCCESS or
        size_dst > 4)
        return std::unexpected(
            fail_t{.err_type = is_fatal ? error_t::fatal : error_t::non_fatal,
                   .msg = "unable to read vm memory"});
    return {};
}

try_op_t aarch64_darwin_process::write_vm_address(mach_vm_address_t addr,
                                                  vm_offset_t source,
                                                  mach_vm_size_t size,
                                                  bool is_fatal) {
    if (mach_vm_write(mach_port_, addr, source, size) != KERN_SUCCESS) {
        return std::unexpected(
            fail_t{.err_type = is_fatal ? error_t::fatal : error_t::non_fatal,
                   .msg = "Unable to write target process memory"});
    }
    return {};
}

try_op_t aarch64_darwin_process::vm_protection_guard(
    std::function<try_op_t(mach_vm_address_t, mach_vm_size_t)> vm_op,
    mach_vm_address_t addr,
    mach_vm_size_t size,
    vm_prot_t original_prot) {
    //
    return try_op_combine(
        set_vm_protection(addr, size,
                          VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY, false)
            .and_then([addr, size, &vm_op]() { return vm_op(addr, size); }),
        set_vm_protection(addr, size, original_prot, true));
}

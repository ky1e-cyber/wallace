
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <cstdio>

#include "aarch64_darwin.hpp"
#include "basic_breakpoint.hpp"
#include "error_types.hpp"

int main(int argc, char* argv[]) {
    auto print_msg_leave = [](fail_t err) {
        printf("%s\n", err.msg.c_str());
        exit(1);
        return err;
    };

    auto process = aarch64_darwin_process::spawn("./test", {})
                       .transform_error(print_msg_leave)
                       .value();

    auto brk = process.set_breakpoint(0x100003f88)
                   .transform_error(print_msg_leave)
                   .transform([&process](basic_breakpoint) {
                       return process.continue_execution();
                   })
                   .transform_error(print_msg_leave);

    int status;
    waitpid(process.get_pid(), &status, 0);

    if (WIFSTOPPED(status)) {
        printf("%d\n", WSTOPSIG(status));
    } else {
        printf("process didn't stopped, status: %x\n", status);
    }

    return 0;
}

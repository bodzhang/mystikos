#include <myst/syscallext.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include "syscall.h"

void do_crt_exit(int code);

/*
 * - If we were cloned with CLONE_VM | CLONE_VFORK we are sharing the process
 *   heap and so also global variables. If this is so we cannot do clean
 *   shutdown, instead we do a terminate instead.
 * - If this process is created from vfork the calling thread in the parent
 *   process is blocked doing a read on this handle to determine when the
 *   process goes away, or the exec was successful.
 */
void exit(int code)
{
    if (!syscall(SYS_myst_is_shared_crt))
        do_crt_exit(code); // original CRT version
    else
        _Exit(code);
    for (;;)
        ;
}

void _Exit(int ec)
{
    syscall(SYS_exit_group, ec);
    for (;;)
        syscall(SYS_exit, ec);
}

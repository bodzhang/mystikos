#define hidden __attribute__((__visibility__("hidden")))

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <pthread_impl.h>

#include <myst/backtrace.h>
#include <myst/lfence.h>
#include <myst/round.h>
#include <myst/setjmp.h>
#include <myst/syscallext.h>
#include <myst/thread.h>

static int _round_up(uint64_t x, uint64_t m, uint64_t* r)
{
    uint64_t t;

    if (!r)
        return -EINVAL;

    /* prevent divide by zero */
    if (m == 0)
        return -ERANGE;

    if (__builtin_add_overflow(x, m - 1, &t))
        return -ERANGE;

    if (__builtin_mul_overflow(t / m, m, r))
        return -ERANGE;

    return 0;
}

/* ATTN: does not work for Linux yet: SYS_arch_prctl */
static void _set_fsbase(void* p)
{
    __asm__ volatile("wrfsbase %0" ::"r"(p));
}

extern hidden unsigned __default_guardsize;
extern hidden unsigned __default_stacksize;
extern hidden volatile size_t __pthread_tsd_size;

extern hidden void* __copy_tls(unsigned char*);

static void _get_parent_stack(void** stack, size_t* stack_size)
{
    struct pthread* self = __pthread_self();

    if (self->stack && self->stack_size)
    {
        *stack = (uint8_t*)self->stack - self->stack_size;
        *stack_size = self->stack_size;
    }
    else
    {
        const long n = SYS_myst_get_process_stack;

        if (syscall(n, stack, stack_size) != 0)
        {
            fprintf(stderr, "cannot retrieve parent stack\n");
            abort();
        }
    }
}

/*
**==============================================================================
**
** _create_child_pthread()
**
** Create a new thread context from the current thread and return a pointer to
** the new pthread structure. The pthread has the following layout.
**
**     [guard|stack|tls|tsd]
**
** Or:
**     [ guard ]                td->guard_size | __default_guardsize
**     [ stack ]                td->stack_size | __default_stacksize
**     [ tls area | tcb ]       __libc.tls_size
**     [ tsd area ]             __pthread_tsd_size
**
**==============================================================================
*/

struct pthread* _create_child_pthread()
{
    size_t size;
    size_t size_rounded;
    struct pthread* self = __pthread_self();
    struct pthread* new;
    uint8_t* map;
    uint8_t* tsd;
    uint8_t* tls;
    uint8_t* stack;            /* bottom */
    uint8_t* stack_limit;      /* top */
    uint8_t* self_stack_limit; /* top */
    size_t stack_size;
    size_t guard_size;
    void* process_stack = NULL;

    _get_parent_stack((void**)&self_stack_limit, &stack_size);

    guard_size = self->guard_size ? self->guard_size : __default_guardsize;
    size = guard_size + stack_size + __libc.tls_size + __pthread_tsd_size;

    _round_up(size, PAGE_SIZE, &size_rounded);

    if (!(map = mmap(
              NULL,
              size_rounded,
              PROT_READ | PROT_WRITE,
              MAP_ANONYMOUS,
              -1,
              0)))
        return NULL;

    /* [guard|stack|tls|tsd] */
    tsd = map + size - __pthread_tsd_size;
    tls = tsd - __libc.tls_size;
    stack = tsd - __libc.tls_size;
    stack_limit = stack - stack_size;

    new = __copy_tls(tls);
    new->self = new;
    new->map_base = map;
    new->map_size = size;
    new->stack = stack;
    new->stack_size = stack - stack_limit;
    new->guard_size = guard_size;
    new->self = new;
    new->tsd = (void*)tsd;

    new->detach_state = DT_DETACHED;
    new->robust_list.head = &new->robust_list.head;
    new->canary = self->canary;
    new->sysinfo = self->sysinfo;

    /* copy over the stack if any */
    memcpy(stack_limit, self_stack_limit, stack_size);

    return new;
}

struct thread_args
{
    myst_jmp_buf_t env;
    void* child_sp;
    void* child_bp;
    volatile pid_t pid;
    struct pthread* child_pthread;

    // [0] - pthread memory and stack
    // [1] - this thread structure
    struct mmap_info
    {
        void* mmap_ptr;
        size_t mmap_ptr_size;
    } unmap_on_exit[2];
};

/* internal musl function */
extern int __clone(int (*func)(void*), void* stack, int flags, void* arg, ...);

/* ATTN: arrange for this function to be called on exit */
__attribute__((__unused__)) static void _thread_args_free(void* arg)
{
    struct thread_args* args = (struct thread_args*)arg;
    /* ATTN: release child stack parent is not process thread */
    free(args);
}

static bool _within(const void* data, size_t size, const void* ptr)
{
    const uint8_t* start = data;
    const uint8_t* end = start + size;
    const uint8_t* p = ptr;
    bool flag = p >= start && p < end;
    return flag;
}

static int _fixup_frame_pointers(
    const void* parent_sp,
    const void* parent_bp,
    void* parent_stack,
    size_t parent_stack_size,
    void* child_stack,
    size_t child_stack_size,
    void** child_sp_out,
    void** child_bp_out)
{
    int ret = -1;
    const ptrdiff_t delta = (uint8_t*)parent_stack - (uint8_t*)child_stack;
    const void* pbp = parent_bp;
    void* cbp = (uint8_t*)pbp - delta;

    if (!_within(parent_stack, parent_stack_size, parent_sp))
    {
        assert("parent stack pointer out of range" == NULL);
        goto done;
    }

    if (!_within(parent_stack, parent_stack_size, parent_bp))
    {
        assert("parent base pointer out of range" == NULL);
        goto done;
    }

    if (!_within(child_stack, child_stack_size, cbp))
    {
        assert("child base pointer out of range" == NULL);
        goto done;
    }

    for (size_t i = 0; pbp; i++)
    {
        *(uint64_t*)cbp -= delta;

        pbp = *(void**)pbp;

        if (!pbp)
            break;

        cbp = *(void**)cbp;

        if (!_within(parent_stack, parent_stack_size, pbp))
        {
            // assert("current parent base pointer out of range" == NULL);
            // goto done;
            break;
        }

        if (!_within(child_stack, child_stack_size, cbp))
        {
            break;
        }

        assert((uint8_t*)cbp + delta == pbp);
    }

    *child_sp_out = (uint8_t*)parent_sp - delta;
    *child_bp_out = (uint8_t*)parent_bp - delta;

    ret = 0;

done:
    return ret;
}

static int _child_func(void* arg)
{
    struct thread_args* args = (struct thread_args*)arg;
    args->env.rsp = (uint64_t)args->child_sp;
    args->env.rbp = (uint64_t)args->child_bp;

    /* set the fsbase register to point to the child_td */
    args->child_pthread->tid = getpid();
    _set_fsbase(args->child_pthread);

    /* set the pid that the parent is waiting on */
    args->pid = getpid();

    /* queue up the cleanup of these memory regions for this process exit */
    /* We cannot safely free the new stack safely because the freeing will
     * return to the same stack before next syscall to exit. */
    syscall(
        SYS_myst_munmap_on_exit,
        args->unmap_on_exit[0].mmap_ptr,
        args->unmap_on_exit[1].mmap_ptr_size);
    syscall(
        SYS_myst_munmap_on_exit,
        args->unmap_on_exit[1].mmap_ptr,
        args->unmap_on_exit[1].mmap_ptr_size);

    /* jump back but on the new child stack */
    myst_longjmp(&args->env, 1);
    return 0;
}

__attribute__((__returns_twice__))
__attribute__((__optimize__("-fno-stack-protector"))) pid_t
myst_fork(void)
{
    pid_t pid = 0;
    myst_jmp_buf_t env;

    if (myst_setjmp(&env) == 0) /* parent */
    {
        struct thread_args* args;
        size_t args_size;
        const void* parent_sp = (const void*)env.rsp;
        const void* parent_bp = (const void*)env.rbp;
        void* sp = NULL;
        void* bp = NULL;
        const int clone_flags = CLONE_VM | CLONE_VFORK | SIGCHLD;
        long tmp_ret;
        struct pthread* child_pthread;
        void* parent_stack;
        void* stack;
        size_t stack_size;
        size_t parent_stack_size;

        if (!(child_pthread = _create_child_pthread()))
            return -ENOMEM;

        stack = (uint8_t*)child_pthread->stack - child_pthread->stack_size;
        stack_size = child_pthread->stack_size;

        _get_parent_stack(&parent_stack, &parent_stack_size);

        assert(stack_size == parent_stack_size);

        if (_fixup_frame_pointers(
                parent_sp,
                parent_bp,
                parent_stack,
                parent_stack_size,
                stack,
                stack_size,
                &sp,
                &bp) != 0)
        {
            munmap(child_pthread->map_base, child_pthread->map_size);
            return -ENOMEM;
        }

        args_size = sizeof(struct thread_args);
        _round_up(sizeof(struct thread_args), PAGE_SIZE, &args_size);
        if (!(args = mmap(
                  NULL,
                  args_size,
                  PROT_READ | PROT_WRITE,
                  MAP_ANONYMOUS,
                  -1,
                  0)))
        {
            munmap(child_pthread->map_base, child_pthread->map_size);
            return -ENOMEM;
        }

        // the map region is probably aligned, but to be sure...
        size_t mmap_rounded_size;
        _round_up(child_pthread->map_size, PAGE_SIZE, &mmap_rounded_size);

        memcpy(&args->env, &env, sizeof(args->env));
        args->child_sp = sp;
        args->child_bp = bp;
        args->child_pthread = child_pthread;
        args->unmap_on_exit[0].mmap_ptr = child_pthread->map_base;
        args->unmap_on_exit[0].mmap_ptr_size = mmap_rounded_size;
        args->unmap_on_exit[1].mmap_ptr = args;
        args->unmap_on_exit[1].mmap_ptr_size = sizeof(args);

        if ((tmp_ret = __clone(_child_func, sp, clone_flags, args)) < 0)
        {
            munmap(child_pthread->map_base, child_pthread->map_size);
            munmap(args, args_size);
            return tmp_ret;
        }

        /* wait for child to set args->pid */
        {
            struct timespec req;
            req.tv_sec = 0;
            req.tv_nsec = 1000;
            while (args->pid == 0)
                nanosleep(&req, NULL);

            pid = args->pid;
        }
    }
    else /* child */
    {
        pid = 0;
    }

    return pid;
}

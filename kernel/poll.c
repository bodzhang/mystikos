// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <errno.h>
#include <poll.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>

#include <myst/defs.h>
#include <myst/eraise.h>
#include <myst/fdops.h>
#include <myst/fdtable.h>
#include <myst/signal.h>
#include <myst/sockdev.h>
#include <myst/syscall.h>
#include <myst/tcall.h>
#include <myst/thread.h>
#include <myst/time.h>

long _poll_kernel(struct pollfd* fds, nfds_t nfds)
{
    long ret = 0;
    myst_fdtable_t* fdtable;
    long total = 0;

    if (!(fdtable = myst_fdtable_current()))
        ERAISE(-ENOSYS);

    for (nfds_t i = 0; i < nfds; i++)
    {
        myst_fdtable_type_t type;
        myst_fdops_t* fdops;
        void* object;
        int events;

        fds[i].revents = 0;

        /* get the device for this file descriptor */
        int res = myst_fdtable_get_any(
            fdtable, fds[i].fd, &type, (void**)&fdops, (void**)&object);
        if (res == -ENOENT)
            continue;
        ECHECK(res);

        if ((events = (*fdops->fd_get_events)(fdops, object)) >= 0)
        {
            fds[i].revents = events;

            if (events)
                total++;
        }
        else if (events != -ENOTSUP)
        {
            continue;
        }
    }

    ret = total;

done:
    return ret;
}

static long _syscall_poll(struct pollfd* fds, nfds_t nfds, int timeout)
{
    long ret = 0;
    myst_fdtable_t* fdtable;
    struct pollfd* tfds = NULL; /* target file descriptors */
    struct pollfd* kfds = NULL; /* kernel file descriptors */
    nfds_t tnfds = 0;           /* number of target file descriptors */
    nfds_t knfds = 0;           /* number of kernel file descriptors */
    size_t* tindices = NULL;    /* target indices */
    size_t* kindices = NULL;    /* kernel indices */
    long tevents = 0;           /* the number of target events */
    long kevents = 0;           /* the number of kernel events */
    static myst_spinlock_t _lock;
    bool locked = false;
    int original_timeout = timeout;
    long lapsed = 0;
    long has_signals = 0;

    printf("_syscall_poll: nfds=%ld, timeout=%d \n", nfds, timeout);

    /* special case: if nfds is zero */
    if (nfds == 0)
    {
        long r;
        long params[6] = {(long)NULL, nfds, timeout};
        ECHECK((r = myst_tcall(SYS_poll, params)));
        ret = r;
        goto done;
    }

    if (!fds && nfds)
        ERAISE(-EFAULT);

    if (!(fdtable = myst_fdtable_current()))
        ERAISE(-ENOSYS);

    if (!(tfds = calloc(nfds, sizeof(struct pollfd))))
        ERAISE(-ENOMEM);

    if (!(kfds = calloc(nfds, sizeof(struct pollfd))))
        ERAISE(-ENOMEM);

    if (!(tindices = calloc(nfds, sizeof(size_t))))
        ERAISE(-ENOMEM);

    if (!(kindices = calloc(nfds, sizeof(size_t))))
        ERAISE(-ENOMEM);

    myst_spin_lock(&_lock);
    locked = true;

    /* Split fds[] into two arrays: tfds[] (target) and kfds[] (kernel) */
    for (nfds_t i = 0; i < nfds; i++)
    {
        int tfd;
        myst_fdtable_type_t type;
        myst_fdops_t* fdops;
        void* object;

        /* get the device for this file descriptor */
        int res = (myst_fdtable_get_any(
            fdtable, fds[i].fd, &type, (void**)&fdops, (void**)&object));

        if (res == -ENOENT)
            continue;
        ECHECK(res);

        /* get the target fd for this object (or -ENOTSUP) */
        if ((tfd = (*fdops->fd_target_fd)(fdops, object)) >= 0)
        {
            tfds[tnfds].events = fds[i].events;
            tfds[tnfds].fd = tfd;
            tindices[tnfds] = i;
            tnfds++;
        }
        else if (tfd == -ENOTSUP)
        {
            kfds[knfds].events = fds[i].events;
            kfds[knfds].fd = fds[i].fd;
            kindices[knfds] = i;
            knfds++;
        }
        else
        {
            continue;
        }
    }

    // get start time
    struct timespec start;
    myst_syscall_clock_gettime(CLOCK_MONOTONIC, &start);

    while (1)
    {
        struct timespec end;

        if (original_timeout < 0)
            timeout = 500;
        printf("Using timeout %d\n", timeout);

        /* pre-poll for kernel events */
        {
            ECHECK((kevents = _poll_kernel(kfds, knfds)));

            /* if any kernel events were found, change timeout to zero */
            if (kevents)
                timeout = 0;
        }
        printf("knfds=%ld, kevents=%ld\n", knfds, kevents);

        myst_spin_unlock(&_lock);
        locked = false;

        printf("tnfds=%ld\n", tnfds);
        /* poll for target events */
        if (tnfds && tfds)
        {
            ECHECK((tevents = myst_tcall_poll(tfds, tnfds, timeout)));
        }
        else
        {
            ECHECK((tevents = myst_tcall_poll(NULL, tnfds, timeout)));
        }
        printf("tnfds=%ld, tevents=%ld\n", tnfds, tevents);

        /* post-poll for kernel events (avoid if already polled above) */
        if (kevents == 0)
        {
            myst_spin_lock(&_lock);
            locked = true;
            ECHECK((kevents = _poll_kernel(kfds, knfds)));
            myst_spin_unlock(&_lock);
            locked = false;
            printf("kevents=%ld (after second poll) \n", kevents);
        }

        /* update fds[] with the target events */
        for (nfds_t i = 0; i < tnfds; i++)
            fds[tindices[i]].revents = tfds[i].revents;

        /* update fds[] with the kernel events */
        for (nfds_t i = 0; i < knfds; i++)
            fds[kindices[i]].revents = kfds[i].revents;

        ret = tevents + kevents;

        if (ret)
            break;

        if (original_timeout == 0)
            break;

        // get exit time
        myst_syscall_clock_gettime(CLOCK_MONOTONIC, &end);

        // timeout -= exit-time -entry-time
        lapsed += ((end.tv_sec - start.tv_sec) * 1000000000 +
                   (end.tv_nsec - start.tv_nsec)) /
                  1000000;

        printf(
            "Original timeout = %d, lapsed time = %ld\n",
            original_timeout,
            lapsed);
        if ((original_timeout > 0) && ((original_timeout - lapsed) <= 0))
            break;

        if (original_timeout > 0)
            timeout = original_timeout - lapsed;
        else
            timeout = original_timeout;
        printf(
            "Original timeout = %d, lapsed time = %ld, next timeout = %d\n",
            original_timeout,
            lapsed,
            timeout);

        has_signals = myst_signal_has_active_signals(myst_thread_self());
        if (has_signals)
        {
            printf(
                "We have some singals on the thread, breaking out of poll()\n");
            break;
        }

        myst_sleep_msec(10);

        myst_spin_lock(&_lock);
        locked = true;
    }

done:

    if (locked)
        myst_spin_unlock(&_lock);

    if (tfds)
        free(tfds);

    if (kfds)
        free(kfds);

    if (tindices)
        free(tindices);

    if (kindices)
        free(kindices);

    if (has_signals)
    {
        // process signals on the thread if we found some from the loop
        myst_signal_process(myst_thread_self());

        // If we returned here and we had no actual poll results then we should
        // tell the caller we were woken as a result of an interrupt instead so
        // it can retry the poll
        if (ret == 0)
        {
            ret = -EINTR;
            printf("Poll processed signals and we have no actual wake events "
                   "so returning EINTR\n");
        }
    }

    return ret;
}

long myst_syscall_poll(struct pollfd* fds, nfds_t nfds, int timeout)
{
    long ret = 0;
    long r;

    ECHECK((r = _syscall_poll(fds, nfds, timeout)));

    if (r == 0 && timeout < 0)
    {
        // Some applications hang when this function does not return
        // periodically, even when there are no file-descriptor events.
        // To avoid this hang, we return EINTR to fake interruption of poll()
        // by a signal. Any robust application must be prepared to handle
        // EINTR.
        ret = -EINTR;
    }
    else
        ret = r;

done:
    return ret;
}

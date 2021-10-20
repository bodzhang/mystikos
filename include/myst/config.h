// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_CONFIG_H
#define _MYST_CONFIG_H

/* enable interruption of kernel threads blocked on host */
#define MYST_INTERRUPT_WITH_SIGNAL 1

/* select interruption for nanosleep(), poll(), and epoll() */
#if (MYST_INTERRUPT_WITH_SIGNAL == 1)
#define MYST_INTERRUPT_NANOSLEEP_WITH_SIGNAL 1
#define MYST_INTERRUPT_POLL_WITH_SIGNAL 1
#define MYST_INTERRUPT_EPOLL_WITH_SIGNAL 1
#else
#define MYST_INTERRUPT_NANOSLEEP_WITH_SIGNAL -1
#define MYST_INTERRUPT_POLL_WITH_SIGNAL -1
#define MYST_INTERRUPT_EPOLL_WITH_SIGNAL -1
#endif

/* enable tracing of EINTR returns from nanosleep(), poll(), and epoll() */
// #define MYST_TRACE_THREAD_INTERRUPTIONS 1

#define MYST_USE_SIGNAL_STACK

/* Set larger stack for the main thread */
#define MYST_MAIN_SIGNAL_STACK_SIZE (16 * PAGE_SIZE)

/* Set smaller stack size for child threads */
#define MYST_THREAD_SIGNAL_STACK_SIZE (4 * PAGE_SIZE)

#endif /* _MYST_CONFIG_H */

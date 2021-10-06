#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>

#include <myst/eraise.h>
#include <myst/syscall.h>

static bool _fd_is_write_enabled(int fd)
{
    bool ret = false;
    struct pollfd fds[1];
    fds[0].fd = fd;
    fds[0].events = POLLOUT;
    fds[0].revents = 0;

    if (myst_syscall_poll(fds, 1, 0) != 1)
        goto done;

    if ((fds[0].revents & POLLNVAL))
        goto done;

    if (!(fds[0].revents & POLLOUT))
        goto done;

    ret = true;

done:
    return ret;
}

long myst_syscall_sendfile(int out_fd, int in_fd, off_t* offset, size_t count)
{
    long ret = 0;
    ssize_t nwritten = 0;
    off_t original_offset = 0;
    struct locals
    {
        char buf[BUFSIZ];
    };
    struct locals* locals = NULL;

    /* Note: in_fd cannot be a socket according to Linux documentation */
    /* Note: out_fd can be any kind of file (including a socket) */

    if (out_fd < 0 || in_fd < 0)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* if offset is not null, set file offset to this value */
    if (offset)
    {
        /* get the current offset */
        original_offset = lseek(in_fd, 0, SEEK_CUR);
        ECHECK(original_offset);

        /* seek the new offset */
        ECHECK(lseek(in_fd, *offset, SEEK_SET));
    }

    /* copy from in_fd to out_fd */
    {
        ssize_t n;
        size_t r = count;

        // The output fd might be a non-blocking socket. If so, then we must
        // determine ahead of time whether the ensuing write will return EAGAIN.
        // If so, the read should be avoided since it would consume bytes that
        // we would be unable to write (and would be lost). The goal of the
        // _fd_is_write_enabled() function is to detect whether write() would
        // raise EAGAIN (in which case the read() is avoided).
        if (!_fd_is_write_enabled(out_fd))
            return -EAGAIN;

        while (r > 0 && (n = read(in_fd, locals->buf, sizeof(locals->buf))) > 0)
        {
            ssize_t m = write(out_fd, locals->buf, n);

            if (m < 0 || m != n)
                ERAISE(EIO);

            nwritten += m;
            r -= m;

            /* avoid the next read if output fd is not write-enabled */
            if (r > 0 && !_fd_is_write_enabled(out_fd))
            {
                if (nwritten > 0)
                    break;

                return -EAGAIN;
            }
        }
    }

    /* if offset is not null, restore the original offset */
    if (offset)
    {
        /* get the final offset */
        off_t final_offset = lseek(in_fd, 0, SEEK_CUR);
        ECHECK(final_offset);

        /* check that the offset is correct */
        if (*offset + nwritten != final_offset)
            ERAISE(-EIO);

        /* restore the original offset */
        ECHECK(lseek(in_fd, original_offset, SEEK_SET));
        *offset = final_offset;
    }

    /* return the number of bytes written to out_fd */
    ret = nwritten;

done:

    if (locals)
        free(locals);

    return ret;
}

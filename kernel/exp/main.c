#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static ssize_t _readn(int fd, void* data, size_t size, off_t off)
{
    ssize_t ret = 0;
    unsigned char* p = (unsigned char*)data;
    size_t r = size;
    size_t m = 0;

    while (r)
    {
        ssize_t n = pread(fd, p, r, off);

        if (n > 0)
        {
            p += n;
            r -= n;
            m += n;
            off += n;
        }
        else if (n == 0)
        {
            ret = -EIO;
            goto done;
        }
        else
        {
            ret = -errno;
            goto done;
        }
    }

    ret = m;

done:
    return ret;
}

int load_elf(const char* path)
{
    int ret = 0;
    int fd = -1;
    Elf64_Ehdr eh;
    const uint8_t ident[] = {0x7f, 'E', 'L', 'F'};
    Elf64_Shdr* shdrs = NULL;
    char* shstrtab = NULL;

    if (!path)
    {
        ret = -EINVAL;
        goto done;
    }

    /* open the ELF file */
    if ((fd = open(path, O_RDONLY)) < 0)
    {
        ret = -ENOENT;
        goto done;
    }

    /* read the ELF header into memory */
    if (_readn(fd, &eh, sizeof(eh), 0) != sizeof(eh))
    {
        ret = -EIO;
        goto done;
    }

    /* check the ELF magic identifier */
    if (memcmp(eh.e_ident, ident, sizeof(ident)) != 0)
    {
        ret = -EIO;
        goto done;
    }

    /* read the section table into memory */
    {
        const size_t size = eh.e_shnum * eh.e_shentsize;

        if (!(shdrs = malloc(size)))
        {
            ret = -ENOMEM;
            goto done;
        }

        if (_readn(fd, shdrs, size, eh.e_shoff) != size)
        {
            ret = -EIO;
            goto done;
        }

        assert(sizeof(Elf64_Shdr) == eh.e_shentsize);
    }

    /* read the shstrtab (section header string table) into memory */
    {
        const size_t size = shdrs[eh.e_shstrndx].sh_size;
        const size_t offset = shdrs[eh.e_shstrndx].sh_offset;

        if (!(shstrtab = malloc(size)))
        {
            ret = -ENOMEM;
            goto done;
        }

        if (_readn(fd, shstrtab, size, offset) != size)
        {
            ret = -EIO;
            goto done;
        }
    }

    /* print out the names of the setions */
    for (size_t i = 0; i < eh.e_shnum; i++)
    {
        Elf64_Shdr* sh = &shdrs[i];
        const char* name = &shstrtab[sh->sh_name];
        printf("name{%s}\n", name);
    }

done:

    if (fd >= 0)
        close(fd);

    if (shdrs)
        free(shdrs);

    if (shstrtab)
        free(shstrtab);

    return ret;
}

int main(int argc, const char* argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        exit(1);
    }

    if (load_elf(argv[1]) != 0)
    {
        fprintf(stderr, "%s: load_elf() failed\n", argv[0]);
        exit(1);
    }

    return 0;
}

// Code found here:
// https://gist.github.com/wxdao/8a0c83ed6cb2a141d1176499e3f6fc48

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include <TargetConditionals.h>
#if TARGET_CPU_X86
        // Other kinds of Mac OS
#include <sys/kern_control.h>
#include <sys/kern_event.h>
#include <net/if_utun.h>
#endif

int set_nonblocking(int fd)
{
    int flags;

    if (-1 == (flags = fcntl(fd, F_GETFL, 0)))
    {
        flags = 0;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int32_t open_utun(uint64_t num)
{
#if TARGET_CPU_X86
    int err;
    int fd;
    struct sockaddr_ctl addr;
    struct ctl_info info;

    fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0)
    {
        return fd;
    }
    memset(&info, 0, sizeof(info));
    strncpy(info.ctl_name, UTUN_CONTROL_NAME, strlen(UTUN_CONTROL_NAME));
    err = ioctl(fd, CTLIOCGINFO, &info);
    if (err < 0)
    {
        close(fd);
        return err;
    }

    addr.sc_id = info.ctl_id;
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_unit = num + 1; // utunX where X is sc.sc_unit -1

    err = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (err < 0)
    {
        // this utun is in use
        close(fd);
        return err;
    }
    set_nonblocking(fd);
    return fd;
#else
    num = 0;
    return -1;
#endif
}

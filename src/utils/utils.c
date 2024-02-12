#include "utils.h"

#include <sys/resource.h>

void set_max_rlimit(void)
{
    struct rlimit rinf = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &rinf);
    setrlimit(RLIMIT_NOFILE, &rinf);
}

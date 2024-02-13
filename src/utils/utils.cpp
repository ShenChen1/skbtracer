#include "utils.h"

#include <sys/resource.h>

void enforce_infinite_rlimit()
{
    struct rlimit rl = {};

    rl.rlim_max = RLIM_INFINITY;
    rl.rlim_cur = rl.rlim_max;
    setrlimit(RLIMIT_MEMLOCK, &rl);
    setrlimit(RLIMIT_NOFILE, &rl);
}
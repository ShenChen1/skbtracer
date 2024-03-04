#include "utils.h"

extern "C" {
#include <sys/resource.h>
}

void Utils::enforce_infinite_rlimit()
{
    struct rlimit rl = {};
    rl.rlim_max = RLIM_INFINITY;
    rl.rlim_cur = rl.rlim_max;
    setrlimit(RLIMIT_MEMLOCK, &rl);

    rl.rlim_max = 8192;
    rl.rlim_cur = rl.rlim_max;
    setrlimit(RLIMIT_NOFILE, &rl);
}
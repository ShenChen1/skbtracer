#include "symdb.h"
#include <stdio.h>
#include <stdlib.h>

symdb_mgr_t *createSymdbMgr(void)
{
    symdb_mgr_t *mgr = NULL;

    mgr = malloc(sizeof(symdb_mgr_t));
    if (mgr == NULL) {
        return NULL;
    }

    return mgr;
}
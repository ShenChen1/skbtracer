#ifndef __SYMDB_MGR_H__
#define __SYMDB_MGR_H__

#include <stddef.h>

typedef struct symdb_mgr {
    void *priv;
    int (*destroy)(struct symdb_mgr *self);

    int (*get_skb_func_list)(struct symdb_mgr *self, const char ***list, size_t *size);
    int (*get_skb_func_param_pos)(struct symdb_mgr *self, const char *func, int *pos);

} symdb_mgr_t;

symdb_mgr_t *createSymdbMgr();

#endif //__SYMDB_MGR_H__
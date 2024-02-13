#ifndef __SYMDB_MGR_H__
#define __SYMDB_MGR_H__

#include <string>

class SymdbMgr {
public:
    SymdbMgr();

    const std::string get_func_by_addr(unsigned long addr);

};












#include <stddef.h>

typedef struct symdb_mgr {
    void *priv;
    int (*destroy)(struct symdb_mgr *self);

    const char *(*get_func_by_addr)(struct symdb_mgr *self, unsigned long addr);
    unsigned long (*get_addr_by_func)(struct symdb_mgr *self, const char *func);

    int (*get_skb_func_list)(struct symdb_mgr *self, const char ***list, size_t *size);
    int (*get_skb_func_param_pos)(struct symdb_mgr *self, const char *func, int *pos);

} symdb_mgr_t;

symdb_mgr_t *createSymdbMgr();

#endif //__SYMDB_MGR_H__
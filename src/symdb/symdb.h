#ifndef __SYMDB_MGR_H__
#define __SYMDB_MGR_H__

typedef struct symdb_mgr {
    void *priv;
    int (*destroy)(struct symdb_mgr *self);
} symdb_mgr_t;

symdb_mgr_t *createSymdbMgr(void);

#endif //__SYMDB_MGR_H__
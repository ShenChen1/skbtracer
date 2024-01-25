#include "symdb.h"

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "trace_helpers.h"
#include "uthash.h"

typedef struct {
    char *name;
    struct btf *btf;
    UT_hash_handle hh;
} btf_hash_t;

typedef struct {
    char *func_name;
    char *mod_name;
    int skb_pos;
    UT_hash_handle hh;
} skb_func_hash_t;

typedef struct {
    struct btf *vmlinux_btf;
    struct ksyms *ksyms;
    btf_hash_t *btf_hash;
    skb_func_hash_t *skb_func_hash;
} symdb_mgr_priv_t;

static int fulfill_btf_hash(btf_hash_t *btf_hash, const char *mod_name, struct btf *vmlinux_btf)
{
    int err;
    struct btf *btf;

    if (mod_name == NULL || strlen(mod_name) == 0) {
        return -EINVAL;
    }

    btf = btf__load_module_btf(mod_name, vmlinux_btf);
    err = libbpf_get_error(btf);
    if (err) {
        log_error("Failed to load BTF for module %s: %s\n", mod_name, strerror(err));
        return -err;
    }

    // Add into hash
    btf_hash_t *s = calloc(1, sizeof(btf_hash_t));
    s->name = strdup(mod_name);
    s->btf = btf;
    HASH_ADD_STR(btf_hash, name, s);
    return 0;
}

static int iterate_kernel_module(symdb_mgr_priv_t *priv)
{
    char buf[64];
    FILE *f;

    f = fopen("/proc/modules", "r");
    if (!f)
        return false;

    while (fgets(buf, sizeof(buf), f) != NULL) {
        if (sscanf(buf, "%s %*s\n", buf) != 1)
            break;

        if (!module_btf_exists(buf)) {
            continue;
        }

        fulfill_btf_hash(priv->btf_hash, buf, priv->vmlinux_btf);
    }

    fclose(f);
    return 0;
}

static int get_func_param_pos(struct btf *btf, const char *func, const char *param)
{
    const struct btf_type *t_func, *t_func_proto, *t;
    const struct btf_param *p;
    int id, i;

    // Find the BTF ID of the function
    id = btf__find_by_name_kind(btf, func, BTF_KIND_FUNC);
    if (id < 0) {
        return -ENOENT;
    }

    t_func = btf__type_by_id(btf, id);
    if (!t_func || !btf_is_func(t_func)) {
        log_error("Error looking up function type: %s", func);
        return -ENOENT;
    }
    t_func_proto = btf__type_by_id(btf, t_func->type);
    if (!t_func_proto || !btf_is_func_proto(t_func_proto)) {
        log_error("Error looking up function proto type: %s", func);
        return -ENOENT;
    }

    // Print the function parameters
    for (i = 0; i < btf_vlen(t_func_proto); i++) {
        p = btf_params(t_func_proto) + i;
        t = btf__type_by_id(btf, p->type);
        if (!t || !btf_is_ptr(t)) {
            continue;
        }
        t = btf__type_by_id(btf, t->type);
        if (!t || !btf_is_struct(t)) {
            continue;
        }
        if (!strcmp(btf__name_by_offset(btf, t->name_off), param)) {
            log_info("Found param '%s' in %s at postion %d", param, func, i);
            return i;
        }
    }

    return -ENOENT;
}

static int iterate_available_functions(symdb_mgr_priv_t *priv)
{
    FILE *f;
    ssize_t nread;
    size_t len = 0;
    char *line = NULL;
    char sym[128], mod[128];
    const char *availfuncs = "/sys/kernel/debug/tracing/available_filter_functions";
    struct btf *btf;

    f = fopen(availfuncs, "r");
    if (f == NULL) {
        log_error("Failed to open %s\n", availfuncs);
        return -errno;
    }

    while ((nread = getline(&line, &len, f)) != -1) {
        char *bracket = strchr(line, '[');
        if (bracket != NULL) {
            // If a bracket is found, split the line into sym and mod
            sscanf(line, "%s [%s]", sym, mod);
            // Remove the trailing bracket from mod
            mod[strlen(mod) - 1] = '\0';
            // Find the btf for the mod
            btf_hash_t *s;
            HASH_FIND_STR(priv->btf_hash, mod, s);
            if (!s) continue;
            btf = s->btf;
        } else {
            // If no bracket is found, the whole line is sym and mod is empty
            sscanf(line, "%s", sym);
            strcpy(mod, "vmlinux");
            btf = priv->vmlinux_btf;
        }

        // Add into hash
        skb_func_hash_t *s = calloc(1, sizeof(skb_func_hash_t));
        s->func_name = strdup(sym);
        s->mod_name = strdup(mod);
        s->skb_pos = get_func_param_pos(btf, sym, "sk_buff");
        HASH_ADD_STR(priv->skb_func_hash, func_name, s);
    }

    free(line);
    fclose(f);
    return 0;
}

static int symdb_priv_destroy(symdb_mgr_priv_t *priv)
{
    {
        btf_hash_t *s, *tmp;
        HASH_ITER(hh, priv->btf_hash, s, tmp) {
            HASH_DEL(priv->btf_hash, s);
            btf__free(s->btf);
            free(s->name);
            free(s);
        }
    }
    {
        skb_func_hash_t *s, *tmp;
        HASH_ITER(hh, priv->skb_func_hash, s, tmp) {
            HASH_DEL(priv->skb_func_hash, s);
            free(s->func_name);
            free(s->mod_name);
            free(s);
        }
    }

    if (priv->vmlinux_btf) {
        btf__free(priv->vmlinux_btf);
    }
    if (priv->ksyms) {
        ksyms__free(priv->ksyms);
    }
    return 0;
}

static int symdb_priv_init(symdb_mgr_priv_t *priv)
{
    int err;

    priv->vmlinux_btf = btf__load_vmlinux_btf();
    err = libbpf_get_error(priv->vmlinux_btf);
    if (err) {
        log_error("Failed to load vmlinux BTF: %s\n", strerror(err));
        return -err;
    }

    priv->ksyms = ksyms__load();
    if (priv->ksyms == NULL) {
        log_error("Failed to load ksyms\n");
        err = -EPERM;
        goto err;
    }

    iterate_kernel_module(priv);
    iterate_available_functions(priv);
    return 0;

err:
    symdb_priv_destroy(priv);
    return err;
}

//---------------------------------------------------API---------------------------------------------------//

static int symdb_destroy(symdb_mgr_t *self)
{
    int ret;
    symdb_mgr_priv_t *priv = self->priv;

    ret = symdb_priv_destroy(priv);
    if (ret) {
        return ret;
    }

    free(priv);
    free(self);
    return 0;
}

static int symdb_get_skb_func_list(symdb_mgr_t *self, const char ***list, size_t *size)
{
    int i = 0, cnt;
    const char **enties = NULL;
    skb_func_hash_t *s, *tmp;
    symdb_mgr_priv_t *priv = self->priv;

    cnt = HASH_COUNT(priv->skb_func_hash);
    enties = calloc(cnt, sizeof(const char *));
    if (enties == NULL) {
        return -ENOMEM;
    }

    HASH_ITER(hh, priv->skb_func_hash, s, tmp) {
        enties[i++] = s->func_name;
    }

    *list = enties;
    *size = cnt;
    return 0;
}

static int symdb_get_skb_func_param_pos(symdb_mgr_t *self, const char *func, int *pos)
{
    skb_func_hash_t *s;
    symdb_mgr_priv_t *priv = self->priv;

    HASH_FIND_STR(priv->skb_func_hash, func, s);
    if (!s) {
        return -ENOENT;
    }

    *pos = s->skb_pos;
    return 0;
}


symdb_mgr_t *createSymdbMgr()
{
    symdb_mgr_t *mgr = NULL;
    symdb_mgr_priv_t *priv = NULL;

    priv = calloc(1, sizeof(symdb_mgr_priv_t));
    if (priv == NULL) {
        return NULL;
    }
    symdb_priv_init(priv);

    mgr = calloc(1, sizeof(symdb_mgr_t));
    if (mgr == NULL) {
        goto err;
    }
    mgr->priv = priv;
    mgr->destroy = symdb_destroy;
    mgr->get_skb_func_list = symdb_get_skb_func_list;
    mgr->get_skb_func_param_pos = symdb_get_skb_func_param_pos;

    return mgr;

err:
    if (priv) {
        symdb_priv_destroy(priv);
        free(priv);
    }
    return NULL;
}
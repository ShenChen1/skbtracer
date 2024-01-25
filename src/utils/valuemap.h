#ifndef __VALUEMAP_H__
#define __VALUEMAP_H__

#include <stdbool.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#define VALUEMAP_STRUCT(source_type, target_type) \
    struct { \
        source_type source; \
        target_type target; \
    }

#define VALUEMAP_TRY_FIND(enummap, source_value, target_ptr) \
    ( \
        _VALUEMAP_TRY_FIND_INDEX(enummap, source_value), \
        (_valuemap_found_index < ARRAY_SIZE(enummap) ? ((*(target_ptr) = (enummap)[_valuemap_found_index].target), true) : false) \
    )

#define VALUEMAP_TRY_FIND_DYNAMIC(enummap, num, source_value, target_ptr) \
    ( \
        _VALUEMAP_TRY_FIND_INDEX_DYNAMIC(enummap, num, source_value), \
        (_valuemap_found_index < num ? ((*(target_ptr) = (enummap)[_valuemap_found_index].target), true) : false) \
    )

#ifdef DISABLE_LOCAL_THREAD_STORAGE
static size_t _valuemap_found_index __attribute__((__unused__));
#else
static __thread size_t _valuemap_found_index __attribute__((__unused__));
#endif

#define _VALUEMAP_TRY_FIND_INDEX(enummap, source_value) \
    ({ \
        typeof((enummap)[0].source) _source_value = (source_value); \
        size_t _i; \
        for (_i = 0; _i < ARRAY_SIZE(enummap); _i++) { \
            if ((enummap)[_i].source == _source_value) { \
                break; \
            } \
        } \
        _valuemap_found_index = _i; \
    })

#define _VALUEMAP_TRY_FIND_INDEX_DYNAMIC(enummap, num, source_value) \
    ({ \
        typeof((enummap)[0].source) _source_value = (source_value); \
        size_t _i; \
        for (_i = 0; _i < num; _i++) { \
            if ((enummap)[_i].source == _source_value) { \
                break; \
            } \
        } \
        _valuemap_found_index = _i; \
    })

#endif /* __VALUEMAP_H__ */
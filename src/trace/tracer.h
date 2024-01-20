#ifndef __TRACER_H__
#define __TRACER_H__

typedef struct tracer {
    void *priv;
    int (*destroy)(struct tracer *self);

    int (*attach)();
} tracer_t;

tracer_t *createTracer(void);

#endif //__TRACER_H__
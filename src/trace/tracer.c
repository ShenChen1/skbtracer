#include "tracer.h"
#include <stdio.h>
#include <stdlib.h>

tracer_t *createTracer(void)
{
    tracer_t *tracer = NULL;

    tracer = malloc(sizeof(tracer_t));
    if (tracer == NULL) {
        return NULL;
    }

    return tracer;
}
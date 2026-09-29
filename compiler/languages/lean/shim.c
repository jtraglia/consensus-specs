#include <lean/lean.h>

#define SPEC_EXPORT __attribute__((visibility("default"), used))

extern void lean_initialize_runtime_module(void);
extern lean_object *initialize_Spec(uint8_t builtin);
extern lean_object *spec_dispatch(lean_object *key, lean_object *args);

static int initialized = 0;

static void spec_init(void) {
    if (initialized) return;
    lean_initialize_runtime_module();
    lean_object *result = initialize_Spec(1);
    if (lean_io_result_is_ok(result)) {
        lean_dec_ref(result);
    } else {
        lean_io_result_show_error(result);
        lean_dec(result);
    }
    lean_io_mark_end_initialization();
    initialized = 1;
}

SPEC_EXPORT void *spec_call(const char *key, const uint8_t *args, size_t length) {
    spec_init();
    lean_object *bytes = lean_alloc_sarray(1, length, length);
    uint8_t *target = lean_sarray_cptr(bytes);
    for (size_t index = 0; index < length; index++) {
        target[index] = args[index];
    }
    return (void *)spec_dispatch(lean_mk_string(key), bytes);
}

SPEC_EXPORT size_t spec_size(void *reply) { return lean_sarray_size((lean_object *)reply); }

SPEC_EXPORT const uint8_t *spec_data(void *reply) {
    return lean_sarray_cptr((lean_object *)reply);
}

SPEC_EXPORT void spec_release(void *reply) { lean_dec((lean_object *)reply); }

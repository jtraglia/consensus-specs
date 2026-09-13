#include <lean/lean.h>

/*
 * The bridge between Python's ctypes and the generated Lean dispatcher.
 *
 * leanc compiles against the Lean toolchain's own sysroot, which carries no C
 * standard library headers, so nothing here includes one. The reply stays a
 * Lean object and the caller copies it out before releasing it, which also
 * avoids allocating with an allocator Lean does not own.
 */

/* leanc compiles with -fvisibility=hidden, and LEAN_EXPORT is a no-op outside
   the runtime's own build, so ask for default visibility explicitly. */
#define SPEC_EXPORT __attribute__((visibility("default"), used))

/* Declared by the runtime but absent from lean.h. */
extern void lean_initialize_runtime_module(void);
/* Lake mangles a module initializer as initialize_<lib>_<module>. */
extern lean_object *initialize_Spec_Spec(uint8_t builtin, lean_object *world);
/* The generated dispatcher, exported from Lean. */
extern lean_object *spec_dispatch(lean_object *key, lean_object *args);

static int initialized = 0;

SPEC_EXPORT void spec_lean_init(void) {
    if (initialized) return;
    lean_initialize_runtime_module();
    lean_object *res = initialize_Spec_Spec(1, lean_io_mk_world());
    if (lean_io_result_is_ok(res)) {
        lean_dec_ref(res);
    } else {
        lean_io_result_show_error(res);
        lean_dec(res);
    }
    lean_io_mark_end_initialization();
    initialized = 1;
}

/*
 * Call a spec function by its "<fork>/<preset>/<name>" key.
 *
 * Returns the reply as an opaque handle. Read it with spec_size and
 * spec_data, then hand it to spec_release.
 */
SPEC_EXPORT void *spec_call(const char *key, const uint8_t *args, size_t args_len) {
    spec_lean_init();

    lean_object *lean_key = lean_mk_string(key);
    lean_object *lean_args = lean_alloc_sarray(1, args_len, args_len);
    uint8_t *target = lean_sarray_cptr(lean_args);
    for (size_t i = 0; i < args_len; i++) {
        target[i] = args[i];
    }

    /* The dispatcher takes ownership of both arguments. */
    return (void *)spec_dispatch(lean_key, lean_args);
}

SPEC_EXPORT size_t spec_size(void *reply) { return lean_sarray_size((lean_object *)reply); }

SPEC_EXPORT const uint8_t *spec_data(void *reply) {
    return lean_sarray_cptr((lean_object *)reply);
}

SPEC_EXPORT void spec_release(void *reply) { lean_dec((lean_object *)reply); }

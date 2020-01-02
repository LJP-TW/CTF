#ifndef HXP2019_BG_H_GENERATED_
#define HXP2019_BG_H_GENERATED_
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "wasm-rt.h"

#ifndef WASM_RT_MODULE_PREFIX
#define WASM_RT_MODULE_PREFIX
#endif

#define WASM_RT_PASTE_(x, y) x ## y
#define WASM_RT_PASTE(x, y) WASM_RT_PASTE_(x, y)
#define WASM_RT_ADD_PREFIX(x) WASM_RT_PASTE(WASM_RT_MODULE_PREFIX, x)

/* TODO(binji): only use stdint.h types in header */
typedef uint8_t u8;
typedef int8_t s8;
typedef uint16_t u16;
typedef int16_t s16;
typedef uint32_t u32;
typedef int32_t s32;
typedef uint64_t u64;
typedef int64_t s64;
typedef float f32;
typedef double f64;

extern void WASM_RT_ADD_PREFIX(init)(void);

/* export: 'memory' */
extern wasm_rt_memory_t (*WASM_RT_ADD_PREFIX(Z_memory));
/* export: 'check' */
extern u32 (*WASM_RT_ADD_PREFIX(Z_checkZ_iii))(u32, u32);
/* export: '__wbindgen_malloc' */
extern u32 (*WASM_RT_ADD_PREFIX(Z___wbindgen_mallocZ_ii))(u32);
/* export: '__wbindgen_realloc' */
extern u32 (*WASM_RT_ADD_PREFIX(Z___wbindgen_reallocZ_iiii))(u32, u32, u32);
#ifdef __cplusplus
}
#endif

#endif  /* HXP2019_BG_H_GENERATED_ */

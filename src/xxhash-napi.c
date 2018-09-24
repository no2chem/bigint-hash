#define NAPI_EXPERIMENTAL
#include <node_api.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h> 

#include "xxhash.h"

#define BIT_MASK(n) (~( ((~0ull) << ((n)-1)) << 1 ))
#define MAX_HASH_WIDTH 64

#define XXHASH_64 0
#define XXHASH_32 1

void cleanup_state(napi_env env, void* finalize_data, void* finalize_hint) {
    if (((uint64_t)finalize_hint) == XXHASH_64) {
        XXH64_freeState(finalize_data);
    } else if (((uint64_t)finalize_hint) == XXHASH_32) {
        XXH32_freeState(finalize_data);
    } else {
        napi_throw_error(env, "EINVAL", "Unexpected state type to cleanup");
    }
}

napi_value hash_buffer(napi_env env, napi_callback_info info) {
  napi_value argv[3];
  napi_status status;
  size_t argc = 3;

  status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  assert(status == napi_ok);

  if (argc < 3) {
    napi_throw_error(env, "EINVAL", "Too few arguments");
    return NULL;
  }

  uint32_t hash_type;
  status = napi_get_value_uint32(env, argv[1], &hash_type);
  assert(status == napi_ok);

  uint8_t* data;
  size_t length;
  status = napi_get_buffer_info(env, argv[2], (void**) &data, &length);
  assert(status == napi_ok);

  if (hash_type == XXHASH_64) {
     XXH64_state_t* state;
     status = napi_get_value_external(env, argv[0], (void**) &state);
     assert(status == napi_ok);
     XXH64_update(state, data, length);
  } else if (hash_type == XXHASH_32) {
     XXH32_state_t* state;
     status = napi_get_value_external(env, argv[0], (void**) &state);
     assert(status == napi_ok);
     XXH32_update((XXH32_state_t*) state, data, length);
  } else {
        napi_throw_error(env, "EINVAL", "Unexpected hash type");
  }
  return NULL;
}

napi_value get_hash_digest_buffer(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  napi_status status;
  size_t argc = 2;

  status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  assert(status == napi_ok);

  if (argc < 2) {
    napi_throw_error(env, "EINVAL", "Too few arguments");
    return NULL;
  }
  
  void* state;
  status = napi_get_value_external(env, argv[0], (void**) &state);
  assert(status == napi_ok);

  uint32_t hash_type;
  status = napi_get_value_uint32(env, argv[1], &hash_type);
  assert(status == napi_ok);

  uint8_t* new_buffer;
  napi_value out;

  if (hash_type == XXHASH_64) {
    uint64_t digest = __builtin_bswap64(XXH64_digest((XXH64_state_t*)state));
    status = napi_create_buffer_copy(env, 8,(uint8_t*) &digest, (void**) &new_buffer, &out);
  } else if (hash_type == XXHASH_32) {
    uint32_t digest = __builtin_bswap32(XXH32_digest((XXH32_state_t*)state));
    status = napi_create_buffer_copy(env, 4,(uint8_t*) &digest, (void**) &new_buffer, &out);
  } else {
   napi_throw_error(env, "EINVAL", "Unsupported hashing algorithm");
    return NULL;
  }

  assert(status == napi_ok);

  return out;
}

napi_value get_hash_digest_bigint(napi_env env, napi_callback_info info) {

  napi_value argv[2];
  napi_status status;
  size_t argc = 2;

  status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  assert(status == napi_ok);

  if (argc < 2) {
    napi_throw_error(env, "EINVAL", "Too few arguments");
    return NULL;
  }

  void* state;
  status = napi_get_value_external(env, argv[0], (void**) &state);
  assert(status == napi_ok);

  uint32_t hash_type;
  status = napi_get_value_uint32(env, argv[1], &hash_type);
  assert(status == napi_ok);

  napi_value out;
  if (hash_type == XXHASH_64) {
    status = napi_create_bigint_uint64(env, XXH64_digest((XXH64_state_t*)state), &out);
  } else {
    status = napi_create_bigint_uint64(env, XXH32_digest((XXH32_state_t*) state), &out);
  }

  assert(status == napi_ok);

  return out;
}

napi_value get_hash_handle(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  napi_status status;

  size_t argc = 1;
  status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  assert(status == napi_ok);

  if (argc < 1) {
    napi_throw_error(env, "EINVAL", "Too few arguments");
    return NULL;
  }

  uint32_t hash_type;
  status = napi_get_value_uint32(env, argv[0], &hash_type);
  assert(status == napi_ok);
  uint64_t hash_type64 = hash_type;

  napi_value out;

    if (hash_type == XXHASH_64) {
     XXH64_state_t* state;
     state = XXH64_createState();
     assert(state != NULL);
     XXH64_reset(state, 0);
     status = napi_create_external(env, state, cleanup_state, (void*)hash_type64, &out);
     assert(status == napi_ok);
  } else if (hash_type == XXHASH_32) {
     XXH32_state_t* state;
     state = XXH32_createState();
     assert(state != NULL);
     XXH32_reset(state, 0);
     status = napi_create_external(env, state, cleanup_state, (void*)hash_type64, &out);
     assert(status == napi_ok);
  } else {
        napi_throw_error(env, "EINVAL", "Unexpected hash type");
        return NULL;
  }
  return out;
}


napi_value hash_buffer_oneshot_bigint(napi_env env, napi_callback_info info) {
 napi_value argv[2];
  napi_status status;
  size_t argc = 2;

  status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  assert(status == napi_ok);

  if (argc < 2) {
    napi_throw_error(env, "EINVAL", "Too few arguments");
    return NULL;
  }

  uint32_t hash_type;
  status = napi_get_value_uint32(env, argv[0], &hash_type);
  assert(status == napi_ok);

  uint8_t* data;
  size_t length;
  status = napi_get_buffer_info(env, argv[1], (void**) &data, &length);
  assert(status == napi_ok);

  napi_value out;
  if (hash_type == XXHASH_64) {
    status = napi_create_bigint_uint64(env, XXH64(data, length, 0ULL), &out);
  } else {
    status = napi_create_bigint_uint64(env, XXH32(data, length, 0L), &out);
  }
  assert(status == napi_ok);
  return out;
}

napi_value hash_buffer_oneshot_buffer(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  napi_status status;
  size_t argc = 2;

  status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  assert(status == napi_ok);

  if (argc < 2) {
    napi_throw_error(env, "EINVAL", "Too few arguments");
    return NULL;
  }

  uint32_t hash_type;
  status = napi_get_value_uint32(env, argv[0], &hash_type);
  assert(status == napi_ok);

  uint8_t* data;
  size_t length;
  status = napi_get_buffer_info(env, argv[1], (void**) &data, &length);
  assert(status == napi_ok);

  napi_value out;
  uint8_t* new_buffer;
  if (hash_type == XXHASH_64) {
    uint64_t digest = __builtin_bswap64(XXH64(data, length, 0ULL));
    status = napi_create_buffer_copy(env, 8,(uint8_t*) &digest, (void**) &new_buffer, &out);
  } else if (hash_type == XXHASH_32) {
    uint32_t digest = __builtin_bswap32(XXH32(data, length, 0L));
    status = napi_create_buffer_copy(env, 4,(uint8_t*) &digest, (void**) &new_buffer, &out);
  } else {
   napi_throw_error(env, "EINVAL", "Unsupported hashing algorithm");
    return NULL;
  }
  assert(status == napi_ok);

  return out;
}

napi_value init_all (napi_env env, napi_value exports) {
  napi_value get_hash_handle_fn;
  napi_value get_hash_digest_bigint_fn;
  napi_value get_hash_digest_buffer_fn;
  napi_value hash_buffer_fn;
  napi_value hash_buffer_oneshot_bigint_fn;
  napi_value hash_buffer_oneshot_buffer_fn;

  napi_create_function(env, NULL, 0, get_hash_handle, NULL, &get_hash_handle_fn);
  napi_create_function(env, NULL, 0, get_hash_digest_bigint, NULL, &get_hash_digest_bigint_fn);
  napi_create_function(env, NULL, 0, get_hash_digest_buffer, NULL, &get_hash_digest_buffer_fn);
  napi_create_function(env, NULL, 0, hash_buffer_oneshot_bigint, NULL, &hash_buffer_oneshot_bigint_fn);
  napi_create_function(env, NULL, 0, hash_buffer_oneshot_buffer, NULL, &hash_buffer_oneshot_buffer_fn);
  napi_create_function(env, NULL, 0, hash_buffer, NULL, &hash_buffer_fn);
 
  napi_set_named_property(env, exports, "getHashHandle", get_hash_handle_fn);
  napi_set_named_property(env, exports, "getHashDigestBigInt", get_hash_digest_bigint_fn);
  napi_set_named_property(env, exports, "getHashDigestBuffer", get_hash_digest_buffer_fn);
  napi_set_named_property(env, exports, "hashBufferOneshotBigInt", hash_buffer_oneshot_bigint_fn);
  napi_set_named_property(env, exports, "hashBufferOneshotBuffer", hash_buffer_oneshot_buffer_fn);
  napi_set_named_property(env, exports, "hashBuffer", hash_buffer_fn);

  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init_all);
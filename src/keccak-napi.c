#define NAPI_EXPERIMENTAL
#include <node_api.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h> 

#include "../ext/xkcp/lib/high/Keccak/KeccakSpongeWidth1600.h"

#define  KECCAK_224 0
#define  KECCAK_256 1
#define  KECCAK_384 2
#define  KECCAK_512 3
#define  SHA3_224 4
#define  SHA3_256 5
#define  SHA3_384 6
#define  SHA3_512 7

#define BIT_MASK(n) (~( ((~0ull) << ((n)-1)) << 1 ))
#define MAX_HASH_WIDTH 64

void cleanup_sponge(napi_env env, void* finalize_data, void* finalize_hint) {
    free(finalize_data);
}

napi_value hash_buffer(napi_env env, napi_callback_info info) {
  napi_value argv[2];
  napi_status status;
  size_t argc = 2;

  status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  assert(status == napi_ok);

  if (argc < 2) {
    napi_throw_error(env, "EINVAL", "Too few arguments");
    return NULL;
  }

  KeccakWidth1600_SpongeInstance* handle;
  status = napi_get_value_external(env, argv[0], (void**) &handle);
  assert(status == napi_ok);

  uint8_t* data;
  size_t length;
  status = napi_get_buffer_info(env, argv[1], (void**) &data, &length);
  assert(status == napi_ok);

  KeccakWidth1600_SpongeAbsorb(handle, data, length);
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

  KeccakWidth1600_SpongeInstance* handle;
  status = napi_get_value_external(env, argv[0], (void**) &handle);
  assert(status == napi_ok);

  uint32_t hash_type;
  status = napi_get_value_uint32(env, argv[1], &hash_type);
  assert(status == napi_ok);

  uint32_t digest_size;
  switch(hash_type) {
      case SHA3_224:
      case KECCAK_224:
        digest_size = 28;
        break;
      case SHA3_256:
      case KECCAK_256:
        digest_size = 32;
        break;
      case SHA3_384:
      case KECCAK_384:
        digest_size = 48;
        break;
      case SHA3_512:
      case KECCAK_512:
        digest_size = 64;
        break;
      break;
  }

  uint8_t result[MAX_HASH_WIDTH];

  switch (hash_type) {
    case SHA3_224:
    case SHA3_256:
    case SHA3_384:
    case SHA3_512:
        KeccakWidth1600_SpongeAbsorbLastFewBits(handle, 6);
        break;
    case KECCAK_224:
    case KECCAK_256:
    case KECCAK_384:
    case KECCAK_512:
        KeccakWidth1600_SpongeAbsorbLastFewBits(handle, 0);
        break;
  }

  KeccakWidth1600_SpongeSqueeze(handle, result, digest_size);
  uint8_t* new_buffer;
  napi_value out;
  status = napi_create_buffer_copy(env, digest_size, result, (void**) &new_buffer, &out);
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

  KeccakWidth1600_SpongeInstance* handle;
  status = napi_get_value_external(env, argv[0], (void**) &handle);
  assert(status == napi_ok);

  uint32_t hash_type;
  status = napi_get_value_uint32(env, argv[1], &hash_type);
  assert(status == napi_ok);

  uint32_t digest_size;
  switch(hash_type) {
      case SHA3_224:
      case KECCAK_224:
        digest_size = 28;
        break;
      case SHA3_256:
      case KECCAK_256:
        digest_size = 32;
        break;
      case SHA3_384:
      case KECCAK_384:
        digest_size = 48;
        break;
      case SHA3_512:
      case KECCAK_512:
        digest_size = 64;
        break;
      break;
  }

  uint8_t result[MAX_HASH_WIDTH];

  switch (hash_type) {
    case SHA3_224:
    case SHA3_256:
    case SHA3_384:
    case SHA3_512:
        KeccakWidth1600_SpongeAbsorbLastFewBits(handle, 6);
        break;
    case KECCAK_224:
    case KECCAK_256:
    case KECCAK_384:
    case KECCAK_512:
        KeccakWidth1600_SpongeAbsorbLastFewBits(handle, 0);
        break;
  }
  KeccakWidth1600_SpongeSqueeze(handle, result, digest_size);


  bool not_64_aligned = (digest_size & 0x7) != 0;
  size_t overflow_len = not_64_aligned ? 8 - (digest_size & 0x7) : 0;
  size_t len_in_words = not_64_aligned ? (digest_size >> 3) + 1 : (digest_size >> 3);
  uint8_t aligned_buffer[64];
  if (not_64_aligned) {
    memset(aligned_buffer, 0, sizeof(aligned_buffer));
    memcpy(aligned_buffer, result, digest_size);
  }
  uint64_t* as_64_aligned = (uint64_t*) (not_64_aligned ? aligned_buffer : result);

  size_t overflow_in_bits = overflow_len << 3; // == overflow_len * 8
  if (len_in_words == 1) {
      as_64_aligned[0] = not_64_aligned ? __builtin_bswap64(as_64_aligned[0]) >> overflow_in_bits :  __builtin_bswap64(as_64_aligned[0]);
  } else {
      uint64_t temp;
      size_t last_word = len_in_words - 1;
      size_t end_ptr = last_word;
      int32_t offset;
      for (offset = 0; offset < (int32_t)(len_in_words / 2); offset++) {
          temp = as_64_aligned[offset];
          as_64_aligned[offset] = as_64_aligned[end_ptr];
          as_64_aligned[end_ptr] = temp;
          end_ptr--;
      } 
      uint64_t prev_overflow = 0;
      for (offset = last_word; offset >= 0; offset--) {
          uint64_t as_little_endian = __builtin_bswap64(as_64_aligned[offset]);
          uint64_t overflow = as_little_endian & BIT_MASK(overflow_in_bits);
          as_64_aligned[offset] = not_64_aligned ? (as_little_endian >> overflow_in_bits) | prev_overflow : as_little_endian;
          prev_overflow = overflow << (64 - overflow_in_bits);
      }
  }

  napi_value out;
  status = napi_create_bigint_words(env, 0, len_in_words, as_64_aligned, &out);
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

  KeccakWidth1600_SpongeInstance* sponge;
  sponge = malloc(sizeof(KeccakWidth1600_SpongeInstance));
  assert(sponge != NULL);

  switch(hash_type) {
      case SHA3_224:
      case KECCAK_224:
        KeccakWidth1600_SpongeInitialize(sponge, 1152, 448);
        break;
      case SHA3_256:
      case KECCAK_256:
        KeccakWidth1600_SpongeInitialize(sponge, 1088, 512);
        break;
      case SHA3_384:
      case KECCAK_384:
        KeccakWidth1600_SpongeInitialize(sponge, 832, 768);
        break;
      case SHA3_512:
      case KECCAK_512:
        KeccakWidth1600_SpongeInitialize(sponge, 576, 1024);
        break;
      break;
  }

  napi_value out;
  status = napi_create_external(env, sponge, cleanup_sponge, NULL, &out);
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


  KeccakWidth1600_SpongeInstance sponge;

  switch(hash_type) {
      case SHA3_224:
      case KECCAK_224:
        KeccakWidth1600_SpongeInitialize(&sponge, 1152, 448);
        break;
      case SHA3_256:
      case KECCAK_256:
        KeccakWidth1600_SpongeInitialize(&sponge, 1088, 512);
        break;
      case SHA3_384:
      case KECCAK_384:
        KeccakWidth1600_SpongeInitialize(&sponge, 832, 768);
        break;
      case SHA3_512:
      case KECCAK_512:
        KeccakWidth1600_SpongeInitialize(&sponge, 576, 1024);
        break;
      break;
  }


  uint32_t digest_size;
  switch(hash_type) {
      case SHA3_224:
      case KECCAK_224:
        digest_size = 28;
        break;
      case SHA3_256:
      case KECCAK_256:
        digest_size = 32;
        break;
      case SHA3_384:
      case KECCAK_384:
        digest_size = 48;
        break;
      case SHA3_512:
      case KECCAK_512:
        digest_size = 64;
        break;
      break;
  }


  uint8_t digest[MAX_HASH_WIDTH];
  KeccakWidth1600_SpongeAbsorb(&sponge, data, length);

  switch (hash_type) {
    case SHA3_224:
    case SHA3_256:
    case SHA3_384:
    case SHA3_512:
        KeccakWidth1600_SpongeAbsorbLastFewBits(&sponge, 6);
        break;
    case KECCAK_224:
    case KECCAK_256:
    case KECCAK_384:
    case KECCAK_512:
        KeccakWidth1600_SpongeAbsorbLastFewBits(&sponge, 0);
        break;
  }

  KeccakWidth1600_SpongeSqueeze(&sponge, digest, digest_size);

  bool not_64_aligned = (digest_size & 0x7) != 0;
  size_t overflow_len = not_64_aligned ? 8 - (digest_size & 0x7) : 0;
  size_t len_in_words = not_64_aligned ? (digest_size >> 3) + 1 : (digest_size >> 3);
  uint8_t aligned_buffer[64];
  if (not_64_aligned) {
    memset(aligned_buffer, 0, sizeof(aligned_buffer));
    memcpy(aligned_buffer, digest, digest_size);
  }
  uint64_t* as_64_aligned = (uint64_t*) (not_64_aligned ? aligned_buffer : digest);

  size_t overflow_in_bits = overflow_len << 3; // == overflow_len * 8
  if (len_in_words == 1) {
      as_64_aligned[0] = not_64_aligned ? __builtin_bswap64(as_64_aligned[0]) >> overflow_in_bits :  __builtin_bswap64(as_64_aligned[0]);
  } else {
      uint64_t temp;
      size_t last_word = len_in_words - 1;
      size_t end_ptr = last_word;
      int32_t offset;
      for (offset = 0; offset < (int32_t)(len_in_words / 2); offset++) {
          temp = as_64_aligned[offset];
          as_64_aligned[offset] = as_64_aligned[end_ptr];
          as_64_aligned[end_ptr] = temp;
          end_ptr--;
      } 
      uint64_t prev_overflow = 0;
      for (offset = last_word; offset >= 0; offset--) {
          uint64_t as_little_endian = __builtin_bswap64(as_64_aligned[offset]);
          uint64_t overflow = as_little_endian & BIT_MASK(overflow_in_bits);
          as_64_aligned[offset] = not_64_aligned ? (as_little_endian >> overflow_in_bits) | prev_overflow : as_little_endian;
          prev_overflow = overflow << (64 - overflow_in_bits);
      }
  }

  napi_value out;
  status = napi_create_bigint_words(env, 0, len_in_words, as_64_aligned, &out);
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


  KeccakWidth1600_SpongeInstance sponge;

  switch(hash_type) {
      case SHA3_224:
      case KECCAK_224:
        KeccakWidth1600_SpongeInitialize(&sponge, 1152, 448);
        break;
      case SHA3_256:
      case KECCAK_256:
        KeccakWidth1600_SpongeInitialize(&sponge, 1088, 512);
        break;
      case SHA3_384:
      case KECCAK_384:
        KeccakWidth1600_SpongeInitialize(&sponge, 832, 768);
        break;
      case SHA3_512:
      case KECCAK_512:
        KeccakWidth1600_SpongeInitialize(&sponge, 576, 1024);
        break;
      break;
  }


  uint32_t digest_size;
  switch(hash_type) {
      case SHA3_224:
      case KECCAK_224:
        digest_size = 28;
        break;
      case SHA3_256:
      case KECCAK_256:
        digest_size = 32;
        break;
      case SHA3_384:
      case KECCAK_384:
        digest_size = 48;
        break;
      case SHA3_512:
      case KECCAK_512:
        digest_size = 64;
        break;
      break;
  }

  KeccakWidth1600_SpongeAbsorb(&sponge, data, length);

  switch (hash_type) {
    case SHA3_224:
    case SHA3_256:
    case SHA3_384:
    case SHA3_512:
        KeccakWidth1600_SpongeAbsorbLastFewBits(&sponge, 6);
        break;
    case KECCAK_224:
    case KECCAK_256:
    case KECCAK_384:
    case KECCAK_512:
        KeccakWidth1600_SpongeAbsorbLastFewBits(&sponge, 0);
        break;
  }

  napi_value out;
  uint8_t* digest;
  status = napi_create_buffer(env, digest_size, (void**) &digest, &out);
  assert(status == napi_ok);
  KeccakWidth1600_SpongeSqueeze(&sponge, digest, digest_size);

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
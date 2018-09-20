#define NAPI_EXPERIMENTAL
#include <node_api.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h> 

#include <openssl/evp.h>

#define MAX_DIGEST_SIZE 64
#define BIT_MASK(n) (~( ((~0ull) << ((n)-1)) << 1 ))


void cleanup_context(napi_env env, void* finalize_data, void* finalize_hint) {
    EVP_MD_CTX_free(finalize_data);
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

  EVP_MD_CTX* handle;
  status = napi_get_value_external(env, argv[0], (void**) &handle);
  assert(status == napi_ok);

  uint8_t* data;
  size_t length;
  status = napi_get_buffer_info(env, argv[1], (void**) &data, &length);
  assert(status == napi_ok);

  assert(EVP_DigestUpdate(handle, data, length) == 1);
  
  return NULL;
}

napi_value get_hash_digest_buffer(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  napi_status status;
  size_t argc = 1;

  status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  assert(status == napi_ok);

  if (argc < 1) {
    napi_throw_error(env, "EINVAL", "Too few arguments");
    return NULL;
  }

  EVP_MD_CTX* handle;
  status = napi_get_value_external(env, argv[0], (void**) &handle);
  assert(status == napi_ok);

  uint32_t digest_size;
  uint8_t result[EVP_MAX_MD_SIZE];

  assert(EVP_DigestFinal_ex(handle, result, &digest_size) == 1);

  uint8_t* new_buffer;
  napi_value out;
  status = napi_create_buffer_copy(env, digest_size, result, (void**) &new_buffer, &out);
  assert(status == napi_ok);

  return out;
}

napi_value get_hash_digest_bigint(napi_env env, napi_callback_info info) {
  napi_value argv[1];
  napi_status status;
  size_t argc = 1;

  status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  assert(status == napi_ok);

  if (argc < 1) {
    napi_throw_error(env, "EINVAL", "Too few arguments");
    return NULL;
  }

  EVP_MD_CTX* handle;
  status = napi_get_value_external(env, argv[0], (void**) &handle);
  assert(status == napi_ok);

  uint32_t digest_size;
  uint8_t result[EVP_MAX_MD_SIZE];

  assert(EVP_DigestFinal_ex(handle, result, &digest_size) == 1);
  

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

#define  OPENSSL_MD5 0
#define  OPENSSL_MD4 1
#define  OPENSSL_SHA1 2
#define  OPENSSL_SHA224 3
#define  OPENSSL_SHA256 4
#define  OPENSSL_SHA384 5
#define  OPENSSL_SHA512 6

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

  EVP_MD_CTX* handle;
  handle = EVP_MD_CTX_new();
  assert(handle != NULL);

  switch (hash_type) {
    case OPENSSL_MD4:
      assert(EVP_DigestInit_ex(handle, EVP_md4(), NULL) == 1);
      break;
    case OPENSSL_MD5:
      assert(EVP_DigestInit_ex(handle, EVP_md5(), NULL) == 1);
      break;
    case OPENSSL_SHA1:
      assert(EVP_DigestInit_ex(handle, EVP_sha1(), NULL) == 1);
      break;
    case OPENSSL_SHA224:
      assert(EVP_DigestInit_ex(handle, EVP_sha224(), NULL) == 1);
      break;
    case OPENSSL_SHA256:
      assert(EVP_DigestInit_ex(handle, EVP_sha256(), NULL) == 1);
      break;
    case OPENSSL_SHA384:
      assert(EVP_DigestInit_ex(handle, EVP_sha384(), NULL) == 1);
      break;
    case OPENSSL_SHA512:
      assert(EVP_DigestInit_ex(handle, EVP_sha512(), NULL) == 1);
      break;
    default:
      napi_throw_error(env, "EINVAL", "Invalid hash type!");
      return NULL;
  }

  napi_value out;
  status = napi_create_external(env, handle, cleanup_context, NULL, &out);
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

  EVP_MD_CTX* handle = EVP_MD_CTX_new();
  assert(handle != NULL);
  
  EVP_MD_CTX_set_flags(handle, EVP_MD_CTX_FLAG_ONESHOT);
  switch (hash_type) {
    case OPENSSL_MD4:
      assert(EVP_DigestInit_ex(handle, EVP_md4(), NULL) == 1);
      break;
    case OPENSSL_MD5:
      assert(EVP_DigestInit_ex(handle, EVP_md5(), NULL) == 1);
      break;
    case OPENSSL_SHA1:
      assert(EVP_DigestInit_ex(handle, EVP_sha1(), NULL) == 1);
      break;
    case OPENSSL_SHA224:
      assert(EVP_DigestInit_ex(handle, EVP_sha224(), NULL) == 1);
      break;
    case OPENSSL_SHA256:
      assert(EVP_DigestInit_ex(handle, EVP_sha256(), NULL) == 1);
      break;
    case OPENSSL_SHA384:
      assert(EVP_DigestInit_ex(handle, EVP_sha384(), NULL) == 1);
      break;
    case OPENSSL_SHA512:
      assert(EVP_DigestInit_ex(handle, EVP_sha512(), NULL) == 1);
      break;
    default:
      napi_throw_error(env, "EINVAL", "Invalid hash type!");
      return NULL;
  }


  uint8_t digest[EVP_MAX_MD_SIZE];
  uint32_t algo_len;

  assert(EVP_DigestUpdate(handle, data, length) == 1);
  assert(EVP_DigestFinal_ex(handle, digest, &algo_len) == 1);
  EVP_MD_CTX_free(handle);

  bool not_64_aligned = (algo_len & 0x7) != 0;
  size_t overflow_len = not_64_aligned ? 8 - (algo_len & 0x7) : 0;
  size_t len_in_words = not_64_aligned ? (algo_len >> 3) + 1 : (algo_len >> 3);
  uint8_t aligned_buffer[64];
  if (not_64_aligned) {
    memset(aligned_buffer, 0, sizeof(aligned_buffer));
    memcpy(aligned_buffer, digest, algo_len);
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

  EVP_MD_CTX* handle;
  handle = EVP_MD_CTX_new();
  assert(handle != NULL);
  EVP_MD_CTX_set_flags(handle, EVP_MD_CTX_FLAG_ONESHOT);
  switch (hash_type) {
    case OPENSSL_MD4:
      assert(EVP_DigestInit_ex(handle, EVP_md4(), NULL) == 1);
      break;
    case OPENSSL_MD5:
      assert(EVP_DigestInit_ex(handle, EVP_md5(), NULL) == 1);
      break;
    case OPENSSL_SHA1:
      assert(EVP_DigestInit_ex(handle, EVP_sha1(), NULL) == 1);
      break;
    case OPENSSL_SHA224:
      assert(EVP_DigestInit_ex(handle, EVP_sha224(), NULL) == 1);
      break;
    case OPENSSL_SHA256:
      assert(EVP_DigestInit_ex(handle, EVP_sha256(), NULL) == 1);
      break;
    case OPENSSL_SHA384:
      assert(EVP_DigestInit_ex(handle, EVP_sha384(), NULL) == 1);
      break;
    case OPENSSL_SHA512:
      assert(EVP_DigestInit_ex(handle, EVP_sha512(), NULL) == 1);
      break;
    default:
      napi_throw_error(env, "EINVAL", "Invalid hash type!");
      return NULL;
  }


  uint8_t* digest;
  uint32_t algo_len = EVP_MD_size(EVP_MD_CTX_md(handle));
  assert(EVP_DigestUpdate(handle, data, length) == 1);

  napi_value out;
  status = napi_create_buffer(env, algo_len, (void**) &digest, &out);
  assert(status == napi_ok);

  assert(EVP_DigestFinal_ex(handle, digest, &algo_len) == 1);

  EVP_MD_CTX_free(handle);

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
{
  "targets": [{
    "target_name": "openssl",
    "sources": [
      "src/openssl-napi.c"
    ],
    "link_settings" : {
      "libraries" : [ "-Wl,-rpath,libssl.a" ]
    }
  }, {
   "target_name": "keccak",
    "sources": [
      "src/keccak-napi.c",
      "ext/xkcp/lib/high/Keccak/KeccakSpongeWidth1600.c",
      "ext/xkcp/lib/low/KeccakP-1600/Optimized64/KeccakP-1600-opt64.c"
    ], "include_dirs": 
    ['ext/xkcp/lib/common', 'ext/xkcp/lib/low/KeccakP-1600/Optimized64', 'ext/xkcp/lib/low/KeccakP-1600/Optimized64/LCufullshld',  
    'ext/xkcp/lib/low/KeccakP-1600/Optimized', 'ext/xkcp/lib/low/common'],
    "cflags" : [ "-Wno-unused-function" , "-march=native"],
      "xcode_settings": {
          "OTHER_CFLAGS": [
            "-Wno-unused-function", "-march=native"
     ]},
  }, {
   "target_name": "xxhash",
    "sources": [
      "src/xxhash-napi.c",
      "ext/xxHash/xxhash.c",
    ], "include_dirs": 
    ['ext/xxHash/'],
    "cflags" : [ "-Wno-unused-function" , "-march=native"],
      "xcode_settings": {
          "OTHER_CFLAGS": [
            "-Wno-unused-function", "-march=native"
     ]},
  }
  ]    
}
#include <stdint.h>

#define SHA_BLOCK 64
#define SHA_DIGEST 32
#define MAX_KEY 512
#define MAX_SALT 256
#define WORK_MEM 65536

static void *memcpy(void *dst, const void *src, unsigned long n) {
    unsigned char *d=(unsigned char*)dst; const unsigned char *s=(const unsigned char*)src;
    for (unsigned long i=0;i<n;i++) d[i]=s[i];
    return dst;
}

static void *memset(void *dst, int c, unsigned long n) {
    unsigned char *d=(unsigned char*)dst;
    for (unsigned long i=0;i<n;i++) d[i]=(unsigned char)c;
    return dst;
}

typedef struct {
    uint32_t h[8];
    uint64_t bits;
    uint8_t block[SHA_BLOCK];
    uint32_t used;
} sha256_ctx;

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
static uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
static uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
static uint32_t bs0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
static uint32_t bs1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
static uint32_t ss0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
static uint32_t ss1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

static void sha_init(sha256_ctx *c) {
    c->h[0]=0x6a09e667; c->h[1]=0xbb67ae85; c->h[2]=0x3c6ef372; c->h[3]=0xa54ff53a;
    c->h[4]=0x510e527f; c->h[5]=0x9b05688c; c->h[6]=0x1f83d9ab; c->h[7]=0x5be0cd19;
    c->bits=0; c->used=0;
}

static void sha_block(sha256_ctx *c, const uint8_t *p) {
    uint32_t w[64];
    for (int i=0;i<16;i++) w[i]=((uint32_t)p[i*4]<<24)|((uint32_t)p[i*4+1]<<16)|((uint32_t)p[i*4+2]<<8)|p[i*4+3];
    for (int i=16;i<64;i++) w[i]=ss1(w[i-2])+w[i-7]+ss0(w[i-15])+w[i-16];
    uint32_t a=c->h[0],b=c->h[1],d=c->h[3],e=c->h[4],f=c->h[5],g=c->h[6],h=c->h[7],cc=c->h[2];
    for (int i=0;i<64;i++) {
        uint32_t t1=h+bs1(e)+ch(e,f,g)+K[i]+w[i];
        uint32_t t2=bs0(a)+maj(a,b,cc);
        h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }
    c->h[0]+=a; c->h[1]+=b; c->h[2]+=cc; c->h[3]+=d; c->h[4]+=e; c->h[5]+=f; c->h[6]+=g; c->h[7]+=h;
}

static void sha_update(sha256_ctx *c, const uint8_t *p, uint32_t len) {
    c->bits += (uint64_t)len * 8ULL;
    while (len) {
        uint32_t take=SHA_BLOCK-c->used;
        if (take>len) take=len;
        for (uint32_t i=0;i<take;i++) c->block[c->used+i]=p[i];
        c->used+=take; p+=take; len-=take;
        if (c->used==SHA_BLOCK) { sha_block(c,c->block); c->used=0; }
    }
}

static void sha_final(sha256_ctx *c, uint8_t out[32]) {
    uint32_t used=c->used;
    c->block[used++]=0x80;
    if (used>56) { while (used<64) c->block[used++]=0; sha_block(c,c->block); used=0; }
    while (used<56) c->block[used++]=0;
    uint64_t bits=c->bits;
    for (int i=0;i<8;i++) c->block[63-i]=(uint8_t)(bits>>(8*i));
    sha_block(c,c->block);
    for (int i=0;i<8;i++) {
        out[i*4]=(uint8_t)(c->h[i]>>24); out[i*4+1]=(uint8_t)(c->h[i]>>16);
        out[i*4+2]=(uint8_t)(c->h[i]>>8); out[i*4+3]=(uint8_t)c->h[i];
    }
}

static void sha_hash(const uint8_t *p, uint32_t len, uint8_t out[32]) {
    sha256_ctx c; sha_init(&c); sha_update(&c,p,len); sha_final(&c,out);
}

static void hmac_init(sha256_ctx *inner, sha256_ctx *outer, const uint8_t *key, uint32_t key_len) {
    uint8_t khash[32];
    uint8_t block[64];
    if (key_len > 64) { sha_hash(key,key_len,khash); key=khash; key_len=32; }
    for (int i=0;i<64;i++) block[i]=0;
    for (uint32_t i=0;i<key_len;i++) block[i]=key[i];
    uint8_t ipad[64], opad[64];
    for (int i=0;i<64;i++) { ipad[i]=(uint8_t)(block[i]^0x36); opad[i]=(uint8_t)(block[i]^0x5c); }
    sha_init(inner); sha_update(inner,ipad,64);
    sha_init(outer); sha_update(outer,opad,64);
    for (volatile uint32_t i=0;i<sizeof(khash);i++) khash[i]=0;
    for (volatile uint32_t i=0;i<sizeof(block);i++) block[i]=0;
    for (volatile uint32_t i=0;i<sizeof(ipad);i++) ipad[i]=0;
    for (volatile uint32_t i=0;i<sizeof(opad);i++) opad[i]=0;
}

static void hmac_sha256(const uint8_t *key, uint32_t key_len,
                        const uint8_t *a, uint32_t a_len,
                        const uint8_t *b, uint32_t b_len,
                        uint8_t out[32]) {
    sha256_ctx inner, outer;
    uint8_t inner_digest[32];
    hmac_init(&inner,&outer,key,key_len);
    if (a_len) sha_update(&inner,a,a_len);
    if (b_len) sha_update(&inner,b,b_len);
    sha_final(&inner,inner_digest);
    sha_update(&outer,inner_digest,32);
    sha_final(&outer,out);
    for (volatile uint32_t i=0;i<32;i++) inner_digest[i]=0;
}


static uint8_t work_mem[WORK_MEM];

int hmac_export_entry(uint32_t key_ptr, uint32_t key_len,
                       uint32_t data_ptr, uint32_t data_len,
                       uint32_t out_ptr) {
    if (key_len > MAX_KEY || data_len > MAX_SALT ||
        key_ptr > WORK_MEM || key_len > WORK_MEM - key_ptr ||
        data_ptr > WORK_MEM || data_len > WORK_MEM - data_ptr ||
        out_ptr > WORK_MEM || 32 > WORK_MEM - out_ptr) return -2;
    hmac_sha256(work_mem + key_ptr, key_len, work_mem + data_ptr, data_len, 0, 0, work_mem + out_ptr);
    return 0;
}

/*
 * Compute exactly one 32-byte PBKDF2 block. That's sufficient because the
 * verifier size is SHA-256's 32-byte output size (PBKDF2 block #1).
 * JS passes memory pointers, keeping the exported ABI tiny and avoiding malloc.
 */
uint32_t memory_base(void) { return (uint32_t)(uintptr_t)work_mem; }

int pbkdf2_export_entry(uint32_t pass_ptr, uint32_t pass_len,
                       uint32_t salt_ptr, uint32_t salt_len,
                       uint32_t iterations, uint32_t out_ptr) {
    if (pass_len > MAX_KEY || salt_len > MAX_SALT || iterations == 0) return -1;
    if (pass_ptr > WORK_MEM || pass_len > WORK_MEM - pass_ptr ||
        salt_ptr > WORK_MEM || salt_len > WORK_MEM - salt_ptr ||
        out_ptr > WORK_MEM || 32 > WORK_MEM - out_ptr) return -2;
    uint8_t *memory = work_mem;
    const uint8_t *pass = memory + pass_ptr;
    const uint8_t *salt = memory + salt_ptr;
    uint8_t *out = memory + out_ptr;
    uint8_t msg[MAX_SALT + 4];
    uint8_t u[32];
    uint8_t t[32];

    for (uint32_t i=0;i<salt_len;i++) msg[i]=salt[i];
    msg[salt_len+0]=0; msg[salt_len+1]=0; msg[salt_len+2]=0; msg[salt_len+3]=1;
    hmac_sha256(pass,pass_len,msg,salt_len+4,0,0,u);
    for (int i=0;i<32;i++) t[i]=u[i];
    for (uint32_t iter=1;iter<iterations;iter++) {
        hmac_sha256(pass,pass_len,u,32,0,0,u);
        for (int i=0;i<32;i++) t[i]^=u[i];
    }
    for (int i=0;i<32;i++) out[i]=t[i];
    for (volatile uint32_t i=0;i<sizeof(msg);i++) msg[i]=0;
    for (volatile uint32_t i=0;i<32;i++) { u[i]=0; t[i]=0; }
    return 0;
}

/*******************************************************************************************************/
/* Maple cipher a metamorphic mode to HC256, algorithm is designed by Hongjun Wu, and was first published in 2004. It is not patented. */
/* Original HC256 implementation by Copyright � 2016 Odzhan. All Rights Reserved. */
/*******************************************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
/*******************************************************************************************************/
typedef struct _maple_ctx_t {
  uint32_t ctr;
  union {
    uint32_t T[2048];
    struct {
      uint32_t P[1024];
      uint32_t Q[1024];
    };
  };
} maple_ctx;
/*******************************************************************************************************/
#define R(v,n)(((v)>>(n))|((v)<<(32-(n))))
#define SIG0(x)(R((x), 7) ^ R((x),18) ^ ((x) >>  3))
#define SIG1(x)(R((x),17) ^ R((x),19) ^ ((x) >> 10))
#define wz 8
#define ROL(x,y) (((x)<<(y&(wz-1))) | ((x)>>(wz-(y&(wz-1)))))
#define ROR(x,y) (((x)>>(y&(wz-1))) | ((x)<<(wz-(y&(wz-1)))))
#define XOR(x,y) (x^y)
#define NOP(x) (x)
#define INV(x) (~x)
/*******************************************************************************************************/
uint8_t maple_clu(uint8_t AA, uint8_t BB) {
  int meta = (BB % 5);
  switch(meta) {
    case 0:AA = ROR(AA,BB);break;
    case 1:AA = ROL(AA,BB);break;
    case 2:AA = XOR(AA,BB);break;
    case 3:AA = INV(AA);break;
    case 4:AA = NOP(AA);break;
  }
  return AA;
}
/*******************************************************************************************************/
uint32_t maple_generate(maple_ctx* c) {
  uint32_t r, i, i3, i10, i12, i1023;
  uint32_t *x0, *x1;
  uint32_t w0, t;
  t = c->ctr;
  c->ctr = (c->ctr+1) & 0x7ff;
  x0 = c->P; x1 = c->Q;
  if (t > 0x3ff) { x0 = c->Q; x1 = c->P; }
  i     = t          & 0x3ff;
  i3    = (i - 3)    & 0x3ff;
  i10   = (i - 10)   & 0x3ff;
  i1023 = (i - 1023) & 0x3ff;
  x0[i] += x0[i10] + (R(x0[i3],10) ^ R(x0[i1023],23)) + x1[(x0[i3] ^ x0[i1023]) & 0x3ff];
  i12 = (i - 12) & 0x3ff;
  w0 = x0[i12];
  for (r=0, t=0; t<4; t++) { r += x1[w0 & 255]; w0 >>= 8; x1 += 1024/4; }
  return r ^ x0[i];
}
/*******************************************************************************************************/
void maple_setkey(maple_ctx *c, void *key_iv) {
  uint32_t W[4096], i, *x=(uint32_t*)key_iv;
  c->ctr = 0;
  for (i=0; i<16; i++) { W[i] = x[i]; }
  for (i=16; i<4096; i++) { W[i] = SIG1(W[i-2])+W[i-7]+SIG0(W[i-15])+W[i-16]+i; }
  for (i=0; i<2048; i++) { c->T[i] = W[i+512]; }
  for (i=0; i<4096; i++) { maple_generate(c); }
}
/*******************************************************************************************************/
void maple_crypt(maple_ctx *c, void *data, uint32_t len) {
  uint32_t i, j, w, y;
  uint8_t  *x=(uint8_t*)data;
  for (i=0; i<len;) {
    w = maple_generate(c);
    y = maple_generate(c);
    for (j=0; j<4 && i < len; j++) {
      x[i] ^= maple_clu((w & 255),(y & 255));
      i++;
      w >>= 8;
      y >>= 8;
    }
  }
}
/*******************************************************************************************************/
uint8_t pt[]= {
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

// 1. If every byte of the key and IV are with value 0,
//    then the first 32 bytes of the keystream are given as:

uint8_t ct1[]= {
0x5b, 0xc1, 0x76, 0x7a, 0x90, 0x73, 0x81, 0x5e,
0xac, 0x78, 0xec, 0xc6, 0x4e, 0xa3, 0x6c, 0x8b,
0xb9, 0x5d, 0x6a, 0x76, 0x72, 0xbf, 0x96, 0xdd,
0xe8, 0x50, 0xb3, 0x7b, 0x1b, 0x40, 0x03, 0xf5 };

// 2. If every byte of the key and IV are with value 0,
//    except that IV[0] = 1, then the first 32 bytes of the
//    keystream are given as:

uint8_t ct2[]= {
0xaf, 0x1d, 0xa8, 0x40, 0xfe, 0x73, 0x05, 0x3a,
0xa0, 0x3f, 0x42, 0xdd, 0xee, 0xaf, 0x35, 0xc6,
0x03, 0x1f, 0xdf, 0xed, 0x90, 0xa5, 0x25, 0x4d,
0x6e, 0x31, 0x4c, 0xa1, 0x0c, 0x4f, 0xb5, 0x5a };

// 3. If every byte of the key and IV are with value 0,
//    except that key[0] = 0x55, then the first 32 bytes of the
//    keystream are given as:
uint8_t ct3[]= {
0x1c, 0x01, 0x94, 0x13, 0x95, 0x8f, 0x5a, 0xe8,
0x48, 0x35, 0x69, 0x87, 0xba, 0xb3, 0x84, 0xd0,
0x93, 0x47, 0xc9, 0x65, 0xfb, 0x03, 0x75, 0xff,
0xc6, 0x40, 0xef, 0x92, 0x6b, 0x64, 0x41, 0x93 };

uint8_t *ct_tbl[3]={ct1, ct2, ct3};
/*******************************************************************************************************/
int equ(uint8_t x[], uint8_t y[], int len) { return (memcmp(x, y, len) == 0); }
/*******************************************************************************************************/
void bin2hex(void *in, int len) {
  int i;
  uint8_t *p=(uint8_t*)in;
  for (i=0; i<len; i++) {
    if ((i & 7) == 0) { putchar('\n'); }
    printf ("%02x, ", p[i]);
  }
  putchar('\n');
}
/*******************************************************************************************************/
int main(void) {
  uint8_t strm[32];
  maple_ctx  c;
  int i;
  struct {
    uint8_t key[32];
    uint8_t iv[32];
  } key;
  for (i=0; i<3; i++) {
    memset(strm, 0, sizeof(strm));

    memset(key.iv,   0, sizeof(key.iv)); memset(key.key,  0, sizeof(key.key));
    if (i == 1) { key.iv[0]  = 1; } else if (i == 2) { key.key[0] = 0x55; }
    maple_setkey(&c, &key); maple_crypt(&c, strm, 32);
    printf ("\nMAPLE Encrypt Test #%i - %s", (i+1), equ(strm, ct_tbl[i], 32) ? "OK" : "failed");
    bin2hex(strm, 32);

    maple_setkey(&c, &key); maple_crypt(&c, strm, 32);
    printf ("\nMAPLE Decrypt Test #%i - %s", (i+1), equ(strm, pt, 32) ? "OK" : "failed");
    bin2hex(strm, 32);
  }
  return 0;
}
/*******************************************************************************************************/
// EOF
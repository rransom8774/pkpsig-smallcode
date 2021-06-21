#ifndef Xvat162wajoclae2005hwx07ypgdd6z5dsootj232n6mjylp4m7pfc84u7sfuuu2t
#define Xvat162wajoclae2005hwx07ypgdd6z5dsootj232n6mjylp4m7pfc84u7sfuuu2t

/*
 * Authors: Robert Ransom
 *
 * This software is released to the public domain.
 *
 * To the extent permitted by law, this software is provided WITHOUT ANY
 * WARRANTY WHATSOEVER.
 */

#include <stddef.h>
#include <stdint.h>

/* needed for ssize_t */
#include <sys/types.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

/* must be provided by surrounding application; used only in keygen */
int minipkpsig_randombytes(u8 *out, size_t outbytes);

typedef int (*minipkpsig_enum_names_cb)(void *cbdata, const char *name);
int minipkpsig_ps_enum_names(minipkpsig_enum_names_cb cb, void *cbdata);

ssize_t minipkpsig_simple_get_publickey_bytes(const char *psname);
ssize_t minipkpsig_simple_get_signature_bytes(const char *psname);

int minipkpsig_simple_detached_verify(const char *psname, const u8 *sigin, const u8 *msg, size_t msglen, const u8 *pk);

ssize_t minipkpsig_simple_get_secretkey_bytes(const char *psname);
int minipkpsig_simple_detached_sign(const char *psname, u8 *sigout, const u8 *msg, size_t msglen, const u8 *sk);

int minipkpsig_simple_keypair(const char *psname, u8 *pk_out, u8 *sk_out);

#endif


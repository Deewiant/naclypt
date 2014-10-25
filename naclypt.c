#define _DEFAULT_SOURCE
#define _BSD_SOURCE 1
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <sodium/crypto_secretbox.h>
#include <sodium/utils.h>

#include "scrypt/crypto_scrypt.h"

#define LIKELY(x) __builtin_expect((x), 1)
#define UNLIKELY(x) __builtin_expect((x), 0)

#define BUFLEN (8 * 1024 * 1024)

// We will store random nonce data in the zeroes in the output (guaranteed to
// us by BOXZEROBYTES). If we have room for more than BOXZEROBYTES in the
// nonce, we use the number of octets written thus far in total. The rest will
// be zero.
static const size_t NONCE_RANDOMS =
   crypto_secretbox_BOXZEROBYTES < crypto_secretbox_NONCEBYTES
      ? crypto_secretbox_BOXZEROBYTES
      : crypto_secretbox_NONCEBYTES;

static size_t read_full(FILE *f, unsigned char *buf, size_t n) {
   size_t r = 0;
   while (r < n) {
      const size_t x = fread_unlocked(buf + r, 1, n - r, f);
      r += x;
      if (UNLIKELY(!x))
         break;
   }
   return r;
}

static size_t write_full(FILE *f, unsigned char *buf, size_t n) {
   size_t w = 0;
   while (w < n) {
      const size_t x = fwrite_unlocked(buf + w, 1, n - w, f);
      w += x;
      if (UNLIKELY(!x))
         break;
   }
   return w;
}

static void __attribute__ ((cold))
   fill_in_nonce(unsigned char *nonce, uint_fast64_t total_read)
{
   uint_fast64_t n = total_read;
   ssize_t missing = (ssize_t)crypto_secretbox_NONCEBYTES
                   - (ssize_t)crypto_secretbox_BOXZEROBYTES;
   for (size_t i = 0; i < sizeof n && missing > 0; --missing, ++i) {
      nonce[crypto_secretbox_BOXZEROBYTES + i] = (uint8_t)n;
      n >>= 8;
   }
}

int main(int argc, char **argv) {
   if (mlockall(MCL_CURRENT | MCL_FUTURE)) {
      perror("Couldn't mlockall");
      return 5;
   }

   const bool decrypting = argc == 3 && !strcmp(argv[2], "-d");

   if (!decrypting && argc != 5) {
      const char *prog = argc ? argv[0] : "naclypt";
      fprintf(stderr,
              "Usage: %s infile logN r p\n"
              "       %s infile -d\n"
              "\n"
              "Encrypts (with -d, decrypts) data from infile to stdout using "
              "a password given\non stdin. Does authenticated encryption i.e. "
              "provides confidentiality,\nintegrity, and authenticity. (Uses "
              "libsodium's crypto_secretbox.)\n"
              "\n"
              "The password is stretched using scrypt(2^logN,r,p). The "
              "decryptor's output\nwill be all zeroes if the wrong password "
              "is given.\n",
              prog, prog);
      return 2;
   }

   FILE *input = fopen(argv[1], "r");
   if (!input) {
      perror("Couldn't open input file");
      return 1;
   }

   struct stat st;
   if (fstat(fileno(input), &st)) {
      perror("Couldn't fstat input file");
      return 3;
   }

   if (!S_ISREG(st.st_mode)) {
      fprintf(stderr, "Input file doesn't look like a regular file\n");
      return 3;
   }

   unsigned char *ibuf = malloc(BUFLEN),
                 *obuf = malloc(BUFLEN);
   if (!ibuf || !obuf) {
      perror("Couldn't malloc buffers");
      return 4;
   }

   memcpy(obuf, crypto_secretbox_PRIMITIVE, sizeof crypto_secretbox_PRIMITIVE);

   // Obfuscate it a bit.
   for (size_t i = 0; i < sizeof crypto_secretbox_PRIMITIVE; ++i)
      obuf[i] ^= (uint8_t)(0xffU - (i << 5));

   if (decrypting) {
      if (read_full(input, ibuf, sizeof crypto_secretbox_PRIMITIVE)
          != sizeof crypto_secretbox_PRIMITIVE)
      {
         fprintf(stderr, "Invalid input: couldn't read magic\n");
         return 1;
      }
      if (memcmp(ibuf, obuf, sizeof crypto_secretbox_PRIMITIVE)) {
         fprintf(stderr, "Invalid input: bad magic (maybe bad libsodium)\n");
         return 1;
      }
   } else {
      if (write_full(stdout, obuf, sizeof crypto_secretbox_PRIMITIVE)
          != sizeof crypto_secretbox_PRIMITIVE)
      {
         fprintf(stderr, "Couldn't write magic to stdout\n");
         return 1;
      }
   }

   uint8_t scrypt_logn;
   uint32_t scrypt_r, scrypt_p;

#define get_scrypt_param(X, argv_idx, unacceptable, range) do { \
   if (decrypting) { \
      uint8_t buf[sizeof scrypt_##X]; \
      if (read_full(input, buf, sizeof buf) != sizeof buf) { \
         fprintf(stderr, "Invalid input: couldn't read " #X "\n"); \
         return 1; \
      } \
      scrypt_##X = 0; \
      for (size_t i = 0; i < sizeof buf; ++i) { \
         scrypt_##X <<= sizeof scrypt_##X > 1 ? 8 : 0; \
         scrypt_##X += buf[i]; \
      } \
   } else { \
      char *end; \
      scrypt_##X = \
         _Generic(scrypt_##X, \
                  uint8_t:  (uint8_t) strtoul(argv[argv_idx], &end, 10), \
                  uint32_t: (uint32_t)strtoul(argv[argv_idx], &end, 10)); \
      if (*end || !*argv[argv_idx]) \
         goto bad_##X; \
      uint8_t buf[sizeof scrypt_##X]; \
      for (uint32_t n = scrypt_##X, i = sizeof scrypt_##X; i--;) { \
         buf[i] = (uint8_t)n; \
         n >>= 8; \
      } \
      if (write_full(stdout, buf, sizeof buf) != sizeof buf) { \
         fprintf(stderr, "Couldn't write " #X " to stdout\n"); \
         return 1; \
      } \
   } \
   if (unacceptable) { \
bad_##X: \
      fprintf(stderr, "Invalid " #X ": should be a decimal integer in the " \
                      "range " range "\n"); \
      return decrypting ? 1 : 2; \
   } \
} while (0)

   get_scrypt_param(logn, 2, scrypt_logn < 2 || scrypt_logn > 63, "[2, 64)");
   get_scrypt_param(r, 3, !scrypt_r || scrypt_r >= 1ul << 30u, "[1, 2^30)");
   get_scrypt_param(p, 4, !scrypt_p || scrypt_p >= 1ul << 30u, "[1, 2^30)");

   if ((uint64_t)scrypt_r * scrypt_p >= (uint64_t)1 << 30u) {
      fprintf(stderr, "Invalid p and r: their product should be below 2^30, "
                      "not %" PRIu64 "\n", (uint64_t)scrypt_r * scrypt_p);
      return 2;
   }

   if (!decrypting) {
      // http://blog.ircmaxell.com/2014/03/why-i-dont-recommend-scrypt.html
      static const uint64_t wanted = 16*1024*1024;
      const uint64_t scrypt_mem_usage =
         128 * scrypt_r * (((uint64_t)1 << scrypt_logn) + scrypt_p);
      if (scrypt_mem_usage < wanted) {
         fprintf(stderr,
                 "Refusing to accept woefully weak scrypt parameters:\n"
                 "memory usage should be at least %" PRIu64 ", not %" PRIu64
                 "\n", wanted, scrypt_mem_usage);
      }
   }

   FILE *urandom = fopen("/dev/urandom", "r");
   if (!urandom) {
      perror("Couldn't open /dev/urandom");
      return 3;
   }

   if (fstat(fileno(urandom), &st)) {
      perror("Couldn't fstat /dev/urandom");
      return 3;
   }

   if (!(S_ISCHR(st.st_mode) && st.st_rdev == makedev(1, 9))) {
      fputs("/dev/urandom looks invalid, refusing to use it\n", stderr);
      return 3;
   }

   unsigned char salt[crypto_secretbox_KEYBYTES];
   if (decrypting) {
      if (read_full(input, salt, sizeof salt) != sizeof salt) {
         fprintf(stderr, "Invalid input: couldn't read salt\n");
         return 1;
      }
   } else {
      if (read_full(urandom, salt, sizeof salt) != sizeof salt) {
         fprintf(stderr, "/dev/urandom failed to provide\n");
         return 3;
      }
      if (write_full(stdout, salt, sizeof salt) != sizeof salt) {
         fprintf(stderr, "Couldn't write salt to stdout\n");
         return 1;
      }
   }

   uint8_t password[16384];
   const size_t pwlen = read_full(stdin, password, sizeof password);
   if (pwlen == sizeof password)
      fprintf(stderr, "Warning: password truncated at %zu octets\n",
              sizeof password);
   fclose(stdin);

   unsigned char key[crypto_secretbox_KEYBYTES];
   if (crypto_scrypt(password, pwlen, salt, sizeof salt,
                     (uint64_t)1 << scrypt_logn, scrypt_r, scrypt_p,
                     key, sizeof key))
   {
      perror("crypto_scrypt failed");
      return 6;
   }
   sodium_memzero(password, pwlen);

   unsigned char nonce[crypto_secretbox_NONCEBYTES];
   memset(nonce, 0, sizeof nonce);

   uint_fast64_t total_read = 0;
   int_fast32_t new_nonce_in = 0;

   const size_t ioffset = decrypting ? 0 : crypto_secretbox_ZEROBYTES;
   const size_t ooffset = decrypting ? crypto_secretbox_ZEROBYTES : 0;
   const size_t isize = BUFLEN - ioffset;
   if (!decrypting)
      memset(ibuf, 0, ioffset);

   for (;;) {
      // read_full is important so that we get the zero bytes when we expect
      // them (during decryption) and we output them at the right time (during
      // encryption).
      size_t r = read_full(input, ibuf + ioffset, isize);
      if (UNLIKELY(!r))
         return 0;

      if (decrypting && UNLIKELY(r <= ooffset)) {
         fprintf(stderr, "Invalid input: expected at least %zu octets after "
                         "%#zx, got only %zu\n", ooffset, total_read, r);
         return 11;
      }

      const bool need_new_nonce = new_nonce_in <= 0;

      if (decrypting) {
         if (UNLIKELY(need_new_nonce)) {
            memcpy(nonce, ibuf, NONCE_RANDOMS);
            fill_in_nonce(nonce, total_read);
            memset(ibuf, 0, NONCE_RANDOMS);
         } else {
            for (size_t i = 0; i < crypto_secretbox_BOXZEROBYTES; ++i) {
               if (LIKELY(!ibuf[i]))
                  continue;
               fprintf(stderr, "Invalid input: octet %#" PRIxFAST64 " should "
                               "have been zero, not %#x\n",
                               total_read + i, ibuf[i]);
               return 11;
            }
         }

         crypto_secretbox_open(obuf, ibuf, r, nonce, key);
         r -= ooffset;
         total_read += r;
         new_nonce_in -= (int_fast32_t)r;

      } else {
         if (UNLIKELY(need_new_nonce)) {
            if (UNLIKELY(read_full(urandom, nonce, NONCE_RANDOMS)
                         != NONCE_RANDOMS))
            {
               fputs("/dev/urandom failed to provide\n", stderr);
               return 3;
            }
            fill_in_nonce(nonce, total_read);
         }

         new_nonce_in -= (int_fast32_t)r;
         total_read += r;
         r += ioffset;
         crypto_secretbox(obuf, ibuf, r, nonce, key);

         if (UNLIKELY(need_new_nonce))
            memcpy(obuf, nonce, NONCE_RANDOMS);
      }

      if (UNLIKELY(write_full(stdout, obuf + ooffset, r) != r)) {
         fputs("Couldn't write ciphertext to stdout\n", stderr);
         return 1;
      }

      if (UNLIKELY(need_new_nonce)) {
         // Arbitrary value but must be greater than BUFLEN.
         new_nonce_in = INT32_MAX;
      }
   }
}

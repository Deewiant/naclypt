#define _DEFAULT_SOURCE
#define _BSD_SOURCE 1
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <sodium/crypto_secretbox.h>

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
      if (!x)
         break;
   }
   return r;
}

static size_t write_full(FILE *f, unsigned char *buf, size_t n) {
   size_t w = 0;
   while (w < n) {
      const size_t x = fwrite_unlocked(buf + w, 1, n - w, f);
      w += x;
      if (!x)
         break;
   }
   return w;
}

static void fill_in_nonce(unsigned char *nonce, uint_fast64_t total_read) {
   uint_fast64_t n = total_read;
   ssize_t missing = (ssize_t)crypto_secretbox_NONCEBYTES
                   - (ssize_t)crypto_secretbox_BOXZEROBYTES;
   for (size_t i = 0; i < sizeof n && missing > 0; --missing, ++i) {
      nonce[crypto_secretbox_BOXZEROBYTES + i] = (uint8_t)n;
      n >>= 8;
   }
}

int main(int argc, char **argv) {
   if (argc < 2 | argc > 3) {
      fprintf(stderr,
              "Usage: %s key [-d]\n"
              "\n"
              "Encrypts (with -d, decrypts) data from stdin to stdout using "
              "the given key.\nDoes authenticated encryption i.e. provides "
              "confidentiality, integrity, and\nauthenticity. (Uses "
              "libsodium's crypto_secretbox.)\n"
              "\n"
              "key must be exactly %u octets long. Output will be all zeroes "
              "if it's wrong.\n",
              argc ? argv[0] : "naclypt", crypto_secretbox_KEYBYTES);
      return 2;
   }

   if (strlen(argv[1]) != crypto_secretbox_KEYBYTES) {
      fprintf(stderr, "Invalid key: must be %u octets long, not %zu\n",
              crypto_secretbox_KEYBYTES, strlen(argv[1]));
      return 2;
   }

   const unsigned char *key = (unsigned char*)argv[1];
   const bool decrypting = argc > 2 && !strcmp(argv[2], "-d");

   FILE *urandom = fopen("/dev/urandom", "r");
   if (!urandom) {
      perror("Couldn't open /dev/urandom");
      return 3;
   }

   struct stat urstat;
   if (fstat(fileno(urandom), &urstat)) {
      perror("Couldn't fstat /dev/urandom");
      return 3;
   }

   if (!(S_ISCHR(urstat.st_mode) && urstat.st_rdev == makedev(1, 9))) {
      fputs("/dev/urandom looks invalid, refusing to use it\n", stderr);
      return 3;
   }

   unsigned char *ibuf = malloc(BUFLEN),
                 *obuf = malloc(BUFLEN);
   if (!ibuf || !obuf) {
      perror("Couldn't malloc buffers");
      return 4;
   }

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
      size_t r = read_full(stdin, ibuf + ioffset, isize);
      if (!r)
         return 0;

      if (decrypting && r <= ooffset) {
         fprintf(stderr, "Invalid input: expected at least %zu octets after "
                         "%#zx, got only %zu\n", ooffset, total_read, r);
         return 11;
      }

      const bool need_new_nonce = new_nonce_in <= 0;

      if (decrypting) {
         if (need_new_nonce) {
            memcpy(nonce, ibuf, NONCE_RANDOMS);
            fill_in_nonce(nonce, total_read);
            memset(ibuf, 0, NONCE_RANDOMS);
         }

         for (size_t i = 0; i < crypto_secretbox_BOXZEROBYTES; ++i) {
            if (ibuf[i]) {
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
         if (need_new_nonce) {
            if (read_full(urandom, nonce, NONCE_RANDOMS) != NONCE_RANDOMS) {
               fprintf(stderr, "/dev/urandom failed to provide\n");
               return 1;
            }
            fill_in_nonce(nonce, total_read);
         }

         new_nonce_in -= (int_fast32_t)r;
         total_read += r;
         r += ioffset;
         crypto_secretbox(obuf, ibuf, r, nonce, key);

         if (need_new_nonce)
            memcpy(obuf, nonce, NONCE_RANDOMS);
      }

      if (write_full(stdout, obuf + ooffset, r) != r) {
         fputs("Could not write to stdout\n", stderr);
         return 1;
      }

      if (need_new_nonce) {
         // Arbitrary value but must be greater than BUFLEN.
         new_nonce_in = INT32_MAX;
      }
   }
}

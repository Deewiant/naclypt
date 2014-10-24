#include <stdint.h>
#include <stdlib.h>
void memzero_ya_rly(void *, size_t);
void memzero_ya_rly(void *p, size_t l) {
   if (l >= 4) {
      if (l >= 8) {
         volatile uint64_t *v = p;
         do {
            *v++ = 0;
            l -= 8;
         } while (l >= 8);
      } else {
         volatile uint32_t *v = p;
         do {
            *v++ = 0;
            l -= 4;
         } while (l >= 4);
      }
   }
   volatile unsigned char *v = p;
   while (l--)
      *v++ = 0;
}

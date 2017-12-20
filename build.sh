#!/bin/sh
exec clang -std=c11 -o naclypt \
   -W{everything,no-disabled-macro-expansion} \
   -O3 -flto -fuse-ld=gold -march=native \
   naclypt.c -l{argon2,sodium}

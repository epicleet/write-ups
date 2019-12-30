#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <bsd/stdlib.h>

#define S(j,v) ( (v << j) | ((v&0xffffff) >> (24-j)) )

static inline void Speck(uint32_t &x, uint32_t &y, uint32_t l1, uint32_t l0, uint32_t k0) {
    // round
    x = (S(16,x) + y) ^ k0;
    y =  S( 3,y)      ^ x ;
    for (int i = 0; i < 21; i++) {
        // key schedule
        uint32_t l2 = (S(16,l0) + k0) ^ i ;
                 k0 =  S( 3,k0)       ^ l2;
        l0 = l1; l1 = l2;
        // round
        x = (S(16,x) + y) ^ k0;
        y =  S( 3,y)      ^ x ;
    }
    x &= 0xffffff; y &= 0xffffff;
}

static void InvSpeck(uint32_t &x, uint32_t &y, uint32_t l1, uint32_t l0, uint32_t k0) {
    uint32_t k[22];
    // key schedule
    for (int i = 0; i < 21; i++) {
        k[i] = k0;
        uint32_t l2 = (S(16,l0) + k0) ^ i ;
                 k0 =  S( 3,k0)       ^ l2;
        l0 = l1; l1 = l2;
    }
    k[21] = k0;
    // rounds
    for (int i = 21; i >= 0; i--) {
        y ^= x; y = S(21,y);
        x ^= k[i]; x -= y; x = S( 8,x);
    }
    x &= 0xffffff; y &= 0xffffff;
}

int main(int argc, char **argv) {
    alarm(16);

    if (argc != 2) {
        fprintf(stderr, "usage: %s hash\n", argv[0]);
        exit(1);
    }
    uint64_t hash = strtoull(argv[1], NULL, 16);
    uint32_t xg = hash >> 24;
    uint32_t yg = hash & 0xffffff;
    InvSpeck(xg, yg, 0, 0, 9);
    //printf("goal: x=0x%x, y=0x%x\n", xg, yg);

#pragma omp parallel for
    for (uint32_t l0 = arc4random() & 0xffffff; l0 < 0xffffff; l0++) {
        for (uint32_t l1 = arc4random() & 0xffffff; l1 < 0xffffff; l1++) {
            for (uint32_t k0 = arc4random() & 0xffffff; k0 < 0xffffff; k0++) {
                uint32_t x = 0, y = 0;
                Speck(x, y, l0, l1, k0);
                if (x == xg && y == yg) {
                    printf("%06x%06x%06x\n", l0, l1, k0);
                    exit(0);
                }
            }
        }
    }

    return 1;
}

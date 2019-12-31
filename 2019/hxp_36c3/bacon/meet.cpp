#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <bsd/stdlib.h>
#include <unordered_map>
#include <tuple>

using namespace std;

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
    alarm(100);

    if (argc != 2) {
        fprintf(stderr, "usage: %s hash\n", argv[0]);
        exit(1);
    }
    uint64_t hash = strtoull(argv[1], NULL, 16);
    uint32_t xg = hash >> 24, yg = hash;
    InvSpeck(xg, yg, 0, 0, 18);
    fprintf(stderr, "[*] goal: x=0x%x, y=0x%x\n", xg, yg);

    fprintf(stderr, "[*] filling meet in the middle map...\n");
    unordered_map<uint64_t, tuple<uint32_t, uint32_t, uint32_t> > meet;
    #define K(x,y) (((uint64_t)x<<24)|y)
    for (int i = 0; i < (1<<21); i++) {
        uint32_t x = xg, y = yg;
        uint32_t l0 = arc4random(), l1 = arc4random(), k0 = arc4random();
        InvSpeck(x, y, l0, l1, k0);
        meet[K(x,y)] = make_tuple(l0, l1, k0);
    }
    fprintf(stderr, "[*] meet in the middle map filled\n");

    fprintf(stderr, "[*] bruteforcing...\n");
#pragma omp parallel
    {
        uint32_t x = arc4random(), y = arc4random();
        while (true) {
            uint32_t l0 = x, l1 = y;  // use Speck itself as a RNG from now on
            for (uint32_t k0 = 0; k0 <= 0xffffff; k0++) {
                x = y = 0;
                Speck(x, y, l0, l1, k0);
                auto it = meet.find(K(x,y));
                if (it != meet.end()) {
                    auto llk = it->second;
                    fprintf(stderr, "[*] meet: x=0x%x, y=0x%x\n", x, y);
                    printf("%06x%06x%06x%06x%06x%06x\n",
                            l0 & 0xffffff,
                            l1 & 0xffffff,
                            k0 & 0xffffff,
                            get<0>(llk) & 0xffffff,
                            get<1>(llk) & 0xffffff,
                            get<2>(llk) & 0xffffff);
                    exit(0);
                }
            }
        }
    }

    return 1;
}

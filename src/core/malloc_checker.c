#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
// random hash implementation from the internet

#define rot(x, k) (((x) << (k)) | ((x) >> (32 - (k))))

#define mix(a, b, c)                            \
    {                                           \
        a -= c;  a ^= rot(c, 4);  c += b;       \
        b -= a;  b ^= rot(a, 6);  a += c;       \
        c -= b;  c ^= rot(b, 8);  b += a;       \
        a -= c;  a ^= rot(c,16);  c += b;       \
        b -= a;  b ^= rot(a,19);  a += c;       \
        c -= b;  c ^= rot(b, 4);  b += a;       \
    }

#define final(a, b, c)                          \
    {                                           \
        c ^= b; c -= rot(b,14);                 \
        a ^= c; a -= rot(c,11);                 \
        b ^= a; b -= rot(a,25);                 \
        c ^= b; c -= rot(b,16);                 \
        a ^= c; a -= rot(c,4);                  \
        b ^= a; b -= rot(a,14);                 \
        c ^= b; c -= rot(b,24);                 \
    }

uint32_t lookup3 (const void *key,
                  size_t      length,
                  uint32_t    initval)
{
    uint32_t  a,b,c;
    const uint8_t  *k;
    const uint32_t *data32Bit;

    data32Bit = key;
    a = b = c = 0xdeadbeef + (((uint32_t)length)<<2) + initval;

    while (length > 12) {
        a += *(data32Bit++);
        b += *(data32Bit++);
        c += *(data32Bit++);
        mix(a,b,c);
        length -= 12;
    }

    k = (const uint8_t *)data32Bit;
    switch (length) {
    case 12: c += ((uint32_t)k[11])<<24;
// fall through
    case 11: c += ((uint32_t)k[10])<<16;
// fall through
    case 10: c += ((uint32_t)k[9])<<8;
// fall through
    case 9 : c += k[8];
// fall through
    case 8 : b += ((uint32_t)k[7])<<24;
// fall through
    case 7 : b += ((uint32_t)k[6])<<16;
// fall through
    case 6 : b += ((uint32_t)k[5])<<8;
// fall through
    case 5 : b += k[4];
// fall through
    case 4 : a += ((uint32_t)k[3])<<24;
// fall through
    case 3 : a += ((uint32_t)k[2])<<16;
// fall through
    case 2 : a += ((uint32_t)k[1])<<8;
// fall through
    case 1 : a += k[0];
        break;
    case 0 : return c;
    }
    final(a,b,c);
    return c;
}

static uint32_t pointer_hash(uint64_t pointer)
{
    return lookup3(&pointer, sizeof(uint64_t), 0);
}

#define MAX_ALLOCS 1000000

// the last bit of the address if used to keep track of whether it's still there
#define PRESENT_FLAG (1uLL << (sizeof(uint64_t) * 8 - 1))
#define ALLOC_ADDRESS(Addr) ((Addr) & ~PRESENT_FLAG)
#define ALLOC_PRESENT(Addr) ((Addr) & PRESENT_FLAG)

uint64_t alloc_map[MAX_ALLOCS];

uint64_t *find_registry(uint64_t target_addr)
{
    uint64_t *res;
    uint64_t current_hash = target_addr;
    uint64_t current_addr;
    do {
        current_hash = pointer_hash(current_hash);
        res = &alloc_map[current_hash % MAX_ALLOCS];
        uint64_t alloc_meta = *res;
        if (alloc_meta == 0)
            return res;

        current_addr = ALLOC_ADDRESS(alloc_meta);
    } while (current_addr != target_addr);
    return res;
}

void register_alloc(void *mem)
{
    if (!mem)
        return;

    printf("registering %p\n", mem);

    uint64_t target_addr = (unsigned long long)mem;
    uint64_t *registry = find_registry(target_addr);
    uint64_t metadata = *registry;
    assert(!ALLOC_PRESENT(metadata));
    *registry = target_addr | PRESENT_FLAG;
}

void unregister_alloc(void *mem)
{
    if (!mem)
        return;
    printf("unregistering %p\n", mem);
    uint64_t target_addr = (unsigned long long)mem;
    uint64_t *registry = find_registry(target_addr);
    uint64_t metadata = *registry;
    assert(ALLOC_PRESENT(metadata));
    *registry = target_addr;
}

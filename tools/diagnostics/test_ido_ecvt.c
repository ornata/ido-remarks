#include <assert.h>
#include <float.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libc_impl.h"
#include "helpers.h"

int run(uint8_t *mem, int argc, char **argv) {
    const double values[] = {0.0,        -0.0,    1.25,    -1.25,    9.999,     0.000012345,
                             1.81818187, DBL_MIN, DBL_MAX, INFINITY, -INFINITY, NAN};
    const int precision[] = {0, 1, 2, 9, 17, 32};
    mmap_initial_data_range(mem, 0x10000000, 0x10004000);
    setup_libc_data(mem);
    unsigned count = 0;
    for (unsigned i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
        for (unsigned j = 0; j < sizeof(precision) / sizeof(precision[0]); j++) {
            int decpt, sign;
            char expected[4096];
            snprintf(expected, sizeof(expected), "%s", ecvt(values[i], precision[j], &decpt, &sign));
            uint32_t pointer = wrapper_ecvt(mem, values[i], precision[j], 0x10000000, 0x10000004);
            assert(pointer);
            assert((int)MEM_U32(0x10000000) == decpt);
            assert((int)MEM_U32(0x10000004) == sign);
            /* Unrelated host conversion must not corrupt the guest-owned copy. */
            (void)ecvt(567.8, 4, &decpt, &sign);
            for (unsigned k = 0; k <= strlen(expected); k++) {
                assert(MEM_U8(pointer + k) == (unsigned char)expected[k]);
            }
            count++;
        }
    }
    puts("PASS: 72 ecvt values/precisions, guest sign/decpt, terminator, and copied lifetime");
    return count == 72 ? 0 : 1;
}

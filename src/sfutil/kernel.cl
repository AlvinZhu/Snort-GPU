#define SPFAC_ALPHABET_SIZE    256
#define UNROLL_SIZE            32

__kernel __attribute__((reqd_work_group_size(64, 1, 1))) void spfac_kernel_1(__constant unsigned char *xlatcase, __global int *result, const __global unsigned char *T, const __global int *spfacStateTable) {

	int tid = get_global_id(0);
    int pstate, state;

	int nm = 0;
	unsigned char UT;
	
    prefetch((T + tid), 64 * 32);
    //prefetch(spfacStateTable, 258);

    int i, j;

#pragma unroll UNROLL_SIZE
    for (j = 0; j < UNROLL_SIZE; j++){
        state = 0;
        for ( i = UNROLL_SIZE * tid + j; ; i++ ){
            UT = xlatcase[T[i]];
            pstate = state;
            state = spfacStateTable[state * SPFAC_ALPHABET_SIZE + UT];
            if (state == 0){
                break;
            }
            if (state == -1){
                nm = atomic_inc(result);
                result[2 * nm + 1] = pstate;
                result[2 * nm + 2] = i;
                break;
            }

        }
    }
}


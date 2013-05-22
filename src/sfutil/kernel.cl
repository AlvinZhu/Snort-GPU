 __kernel __attribute__((reqd_work_group_size(64, 1, 1))) void spfac_kernel_1(__constant unsigned char *xlatcase, __global int *result, const __global unsigned char *T, const __global int *spfacStateTable) {

	int tid = get_global_id(0);
    int pstate, state;

	int nm = 0;
	unsigned char UT;
	
    prefetch((T + tid), 64 * 32);
    //prefetch(spfacStateTable, 258);

    int i, j;

#pragma unroll 32
    for (j = 0; j < 32; j++){
        state = 0;
        for ( i = 4 * tid + j; ; i++ ){
            UT = xlatcase[T[i]];
            pstate = state;
            state = spfacStateTable[state * 257 + UT];
            if (state == 0){
                if (spfacStateTable[pstate * 257 + 256] == 1){
                    nm = atomic_inc(result);
                    result[2 * nm + 1] = pstate;
                    result[2 * nm + 2] = i;
                }
                break;
            }
        }
    }
}


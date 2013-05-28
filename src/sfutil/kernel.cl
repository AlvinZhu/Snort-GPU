#define SPFAC_ALPHABET_SIZE    256
#define UNROLL_SIZE            32

__kernel __attribute__((reqd_work_group_size(64, 1, 1))) void spfac_kernel_1(__constant unsigned char *xlat_case, __global int *result, const __global unsigned char *text, const __global int *state_table) {

    int pre_state, state;
	int num_match = 0;
	int state_index;
	int tid = get_global_id(0);

    int i, j;

    tid *= UNROLL_SIZE;	
    prefetch((text + tid), UNROLL_SIZE);

#pragma unroll UNROLL_SIZE
    for (j = 0; j < UNROLL_SIZE; j++){
        state = 0;
        for ( i = tid + j; ; i++ ){
            state_index = xlat_case[text[i]];
            pre_state = state;
            state = state_table[state * SPFAC_ALPHABET_SIZE + state_index];
            if (state == 0){
                break;
            }
            if (state == -1){
                num_match = atomic_inc(result);
                result[2 * num_match + 1] = pre_state;
                result[2 * num_match + 2] = i;
                break;
            }
        }
    }
}


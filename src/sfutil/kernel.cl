struct _k_arg_struct {
    int state;
    int n;
    unsigned char T[3072];
};

typedef struct _k_arg_struct k_arg_struct;

__kernel void spfac_kernel_1(__global unsigned char *xlatcase, __global k_arg_struct *kas, __global int *result, __global int *spfacStateTable) {
	int tid = get_global_id(0);
    int pstate, state, current_state = kas->state;
    int n = kas->n;

	int nm = 0;
	unsigned char UT;
	
    int i, j;
    for(j = 0; j < n; j++){
        state = current_state;
        for( i = tid * n + j; i < 384 * n; i++ ){
            UT = xlatcase[kas->T[i]];
            pstate = state;
            state = spfacStateTable[state * (256 + 2) + UT];
            if (state == 0){
                if (spfacStateTable[pstate * (256 + 2) + 256] == 1){
                    nm = atomic_inc(result);
                    result[2 * nm + 1] = pstate;
                    result[2 * nm + 2] = i;
                }
                break;
            }
        }
    }
    
}


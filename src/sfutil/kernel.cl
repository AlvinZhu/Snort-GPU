#define SPFAC_ALPHABET_SIZE    256
#define UNROLL_SIZE            32
#define GROUP_SIZE             64

__kernel __attribute__((reqd_work_group_size(64, 1, 1)))
void spfac_kernel_1(__constant unsigned char *xlat_case, 
        __global int *result, 
        const __global unsigned char *text, 
        const __global int *state_table)
{    
    int pre_state, state;
	int num_match = 0;
	int state_index;

    int i, j;

    int tid = get_global_id(0);
    tid *= UNROLL_SIZE;
    prefetch((text + tid), UNROLL_SIZE);
#pragma unroll
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

__kernel __attribute__((reqd_work_group_size(64, 1, 1)))
void spfac_kernel_2(__constant unsigned char *xlat_case, 
        __global int *result, 
        const __global unsigned char *text, 
        const __global int *state_table)
{    
    int pre_state, state;
	int num_match = 0;
	int state_index;

    int i, j;

    __local unsigned char buf_xc[SPFAC_ALPHABET_SIZE];
    __local unsigned char buf_text[GROUP_SIZE * (UNROLL_SIZE + 1)];
    __local int buf_st[SPFAC_ALPHABET_SIZE];

    int gid = get_group_id(0);
    int lid = get_local_id(0);
    gid *= GROUP_SIZE * UNROLL_SIZE;

#pragma unroll
    for (i = 0; i < SPFAC_ALPHABET_SIZE; i += GROUP_SIZE){
        buf_xc[i + lid] = xlat_case[i + lid];
        buf_st[i + lid] = state_table[i +lid];
    }

#pragma unroll
    for (i = 0; i < GROUP_SIZE * (UNROLL_SIZE + 1); i += GROUP_SIZE){
        buf_text[i + lid] = text[i + gid + lid];
    }
    uchar16 test = vload16(0, text);
    uchar *test2 = (uchar *)(&test);
   

#pragma unroll
    for (j = 0; j < UNROLL_SIZE; j++){
        state_index = buf_xc[buf_text[lid * GROUP_SIZE + j]];
        pre_state = 0;
        state = buf_st[state_index];
        for ( i = lid * GROUP_SIZE + j + 1; ; i++ ){
            if (state == 0){
                break;
            }
            if (state == -1){
                num_match = atomic_inc(result);
                result[2 * num_match + 1] = pre_state;
                result[2 * num_match + 2] = i;
                break;
            }
            state_index = buf_xc[buf_text[i]];
            pre_state = state;
            state = state_table[state * SPFAC_ALPHABET_SIZE + state_index];
        }
    }
}



#define SPFAC_ALPHABET_SIZE    256
#define UNROLL_SIZE            16
#define GROUP_SIZE             64
// kernel1
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
// kernel2: use LDS
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

#pragma unroll
    for (j = 0; j < UNROLL_SIZE; j++){
        state_index = buf_xc[buf_text[lid * UNROLL_SIZE + j]];
        pre_state = 0;
        state = buf_st[state_index];
        for ( i = lid * UNROLL_SIZE + j + 1; ; i++ ){
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
// kernel3: vload
__kernel __attribute__((reqd_work_group_size(64, 1, 1)))
void spfac_kernel_3(__constant uchar *xlat_case,
        __global int *result,
        const __global uchar *text,
        const __global int *state_table)
{
    int pre_state, state;
	int num_match = 0;
	int state_index;

    int i, j;

    __local uchar4 _buf_xc[SPFAC_ALPHABET_SIZE / 4];
    __local uchar16 _buf_text[GROUP_SIZE / 16 * (UNROLL_SIZE + 1)];
    __local int4 _buf_st[SPFAC_ALPHABET_SIZE / 4];

    __local uchar *buf_xc = (__local uchar *)(_buf_xc);
    __local uchar *buf_text = (__local uchar *)(_buf_text);
    __local int *buf_st = (__local int *)(_buf_st);

    int gid = get_group_id(0);
    int lid = get_local_id(0);
    gid *= GROUP_SIZE * UNROLL_SIZE;
    int gid2 = gid / 16;

    _buf_xc[lid] = vload4(lid, xlat_case);
    _buf_st[lid] = vload4(lid, state_table);

    _buf_text[lid] = vload16((gid2 + lid), text);
    _buf_text[GROUP_SIZE + lid] = vload16((gid2+ GROUP_SIZE + lid), text);
    buf_text[GROUP_SIZE * UNROLL_SIZE + lid] = text[gid + GROUP_SIZE * UNROLL_SIZE + lid];

#pragma unroll
    for (j = 0; j < UNROLL_SIZE; j++){
        state_index = buf_xc[buf_text[lid * UNROLL_SIZE + j]];
        pre_state = 0;
        state = buf_st[state_index];
        for ( i = lid * UNROLL_SIZE + j + 1; ; i++ ){
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
// kernel4: reduce bank conflict
// BUG!
struct _text_struct{
    uchar16 text[2];
    int unused;
};
typedef struct _text_struct text_struct;

__kernel __attribute__((reqd_work_group_size(64, 1, 1)))
void spfac_kernel_4(__constant uchar *xlat_case,
        __global int *result,
        const __global uchar *text,
        const __global int *state_table)
{
    int pre_state, state;
	int num_match = 0;
	int state_index;

    int i, j;

    __local uchar4 _buf_xc[SPFAC_ALPHABET_SIZE / 4];
    __local text_struct _buf_text[GROUP_SIZE / 32 * (UNROLL_SIZE + 1)];
    __local int4 _buf_st[SPFAC_ALPHABET_SIZE / 4];

    __local uchar *buf_xc = (__local uchar *)(_buf_xc);
    __local uchar *buf_text = (__local uchar *)(_buf_text);
    __local int *buf_st = (__local int *)(_buf_st);

    int gid = get_group_id(0);
    int lid = get_local_id(0);
    gid *= GROUP_SIZE * UNROLL_SIZE;
    int gid2 = gid / 16;

    _buf_xc[lid] = vload4(lid, xlat_case);
    _buf_st[lid] = vload4(lid, state_table);

    _buf_text[lid >> 1].text[lid & 0x01] = vload16((gid2 + lid), text);
    _buf_text[GROUP_SIZE / 2 + (lid >> 1)].text[lid & 0x01] = vload16((gid2+ GROUP_SIZE + lid), text);
    buf_text[GROUP_SIZE * (UNROLL_SIZE + 4) + lid] = text[gid + GROUP_SIZE * UNROLL_SIZE + lid];

#pragma unroll
    for (j = 0; j < UNROLL_SIZE; j++){
        state_index = buf_xc[buf_text[lid * (UNROLL_SIZE + 4) + j]];
        pre_state = 0;
        state = buf_st[state_index];
        for ( i = lid * (UNROLL_SIZE + 4) + j + 1; ; i++ ){//BUG!!
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
// kernel:5 PFAC(base on kernel3)
__kernel __attribute__((reqd_work_group_size(64, 1, 1)))
void spfac_kernel_5(__constant uchar *xlat_case,
        __global int *result,
        const __global uchar *text,
        const __global int *state_table)
{
    int pre_state, state;
	int num_match = 0;
	int state_index;

    int i, j;

    __local uchar4 _buf_xc[SPFAC_ALPHABET_SIZE / 4];
    __local uchar16 _buf_text[GROUP_SIZE / 16 * (UNROLL_SIZE + 1)];
    __local int4 _buf_st[SPFAC_ALPHABET_SIZE / 4];

    __local uchar *buf_xc = (__local uchar *)(_buf_xc);
    __local uchar *buf_text = (__local uchar *)(_buf_text);
    __local int *buf_st = (__local int *)(_buf_st);

    int gid = get_group_id(0);
    int lid = get_local_id(0);
    gid *= GROUP_SIZE * UNROLL_SIZE;
    int gid2 = gid / 16;

    _buf_xc[lid] = vload4(lid, xlat_case);
    _buf_st[lid] = vload4(lid, state_table);

    _buf_text[lid] = vload16((gid2 + lid), text);
    _buf_text[GROUP_SIZE + lid] = vload16((gid2+ GROUP_SIZE + lid), text);
    buf_text[GROUP_SIZE * UNROLL_SIZE + lid] = text[gid + GROUP_SIZE * UNROLL_SIZE + lid];

#pragma unroll
    for (j = 0; j < UNROLL_SIZE; j++){
        state_index = buf_xc[buf_text[UNROLL_SIZE * j + lid]];
        pre_state = 0;
        state = buf_st[state_index];
        for ( i = UNROLL_SIZE * j + lid + 1; ; i++ ){
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
// kernel6
__kernel __attribute__((reqd_work_group_size(64, 1, 1)))
void spfac_kernel_6(__constant uchar *xlat_case,
        __global int *result,
        const __global uchar *text,
        const __global int *state_table)
{
    int pre_state, state;
	int num_match = 0;
	int state_index;

    int i, j;

    __local uchar buf_xc[SPFAC_ALPHABET_SIZE];
    __local uchar buf_text[GROUP_SIZE * (UNROLL_SIZE + 1)];
    __local int buf_st[SPFAC_ALPHABET_SIZE];

    int gid = get_group_id(0);
    int lid = get_local_id(0);
    gid *= GROUP_SIZE * UNROLL_SIZE;
    int gid2 = gid / 16;

    ((__local uchar4 *)buf_xc)[lid] = vload4(lid, xlat_case);
    ((__local int4 *)buf_st)[lid] = vload4(lid, state_table);

#pragma unroll
    for (i = 0; i < GROUP_SIZE / 16 * UNROLL_SIZE; i += GROUP_SIZE){
        ((__local uchar16 *)buf_text)[lid] = vload16((gid2 + i + lid), text);
    }
    buf_text[GROUP_SIZE * UNROLL_SIZE + lid] = text[gid + GROUP_SIZE * UNROLL_SIZE + lid];

#pragma unroll
    for (j = 0; j < UNROLL_SIZE; j++){
        state_index = buf_xc[buf_text[lid * UNROLL_SIZE + j]];
        pre_state = 0;
        state = buf_st[state_index];
        i = lid * UNROLL_SIZE + j + 1;
        while (state != 0){
            state_index = buf_xc[buf_text[i]];
            pre_state = state;
            state = state_table[state * SPFAC_ALPHABET_SIZE + state_index];

            if (state == -1){
                num_match = atomic_inc(result);
                result[2 * num_match + 1] = pre_state;
                result[2 * num_match + 2] = i;
                state = 0;
            }
            i++;
        }
    }
}


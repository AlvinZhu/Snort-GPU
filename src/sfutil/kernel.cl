__kernel void kernel_1(__global unsigned char *acsmGStates, __global int *tindex, __global int *result) {
	int sSize = tindex[0] + 2;
	int n = tindex[1];
	unsigned char state = tindex[2];
	__global unsigned char* ps;
	
	int nm = 1;
	
	int i;
	for( i = 3; i < 3 + n; i++ )
    {
        ps = &(acsmGStates[ state * sSize]);
        if (ps[1])
        {
           result[nm] = state;
           nm++;
        }
        state = ps[2u + tindex[i]];
    }
    result[nm] = 0;
    result[0] = state;
}

__kernel void kernel_2(__global unsigned short *acsmGStates, __global int *tindex, __global int *result) {
	int sSize = tindex[0] + 2;
	int n = tindex[1];
	unsigned short state = tindex[2];
	__global unsigned short* ps;
	
	int nm = 1;
	
	int i;
	for( i = 3; i < 3 + n; i++ )
    {
        ps = &(acsmGStates[ state * sSize]);
        if (ps[1])
        {
           result[nm] = state;
           nm++;
        }
        state = ps[2u + tindex[i]];
    }
    result[nm] = 0;
    result[0] = state;
}

__kernel void kernel_4(__global unsigned int *acsmGStates, __global int *tindex, __global int *result) {
	int sSize = tindex[0] + 2;
	int n = tindex[1];
	unsigned int state = tindex[2];
	__global unsigned int* ps;
	
	int nm = 1;
	
	int i;
	for( i = 3; i < 3 + n; i++ )
    {
        ps = &(acsmGStates[ state * sSize]);
        if (ps[1])
        {
           result[nm] = state;
           nm++;
        }
        state = ps[2u + tindex[i]];
    }
    result[nm] = 0;
    result[0] = state;
}

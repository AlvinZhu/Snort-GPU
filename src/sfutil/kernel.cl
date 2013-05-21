__kernel __attribute__((reqd_work_group_size(64, 1, 1))) void spfac_kernel_1(__constant unsigned char *xlatcase, __global int *result, const __global unsigned char *T, const __global int *spfacStateTable) {

	int tid = get_global_id(0);
    int pstate, state;

	int nm = 0;
	unsigned char UT;
	
    prefetch((T + tid), 96);
    //prefetch(spfacStateTable, 258);

    int i;
    state = 0;
    for( i = 4 * tid; ; i++ ){
        UT = xlatcase[T[i]];
        pstate = state;
        state = spfacStateTable[state * 258 + UT];
        if (state == 0){
            if (spfacStateTable[pstate * 258 + 256] == 1){
                nm = atomic_inc(result);
                result[2 * nm + 1] = pstate;
                result[2 * nm + 2] = i;
            }
            break;
        }
    }

    state = 0;
    for( i = 4 * tid + 1; ; i++ ){
        UT = xlatcase[T[i]];
        pstate = state;
        state = spfacStateTable[state * 258 + UT];
        if (state == 0){
            if (spfacStateTable[pstate * 258 + 256] == 1){
                nm = atomic_inc(result);
                result[2 * nm + 1] = pstate;
                result[2 * nm + 2] = i;
            }
            break;
        }
    }

    state = 0;
    for( i = 4 * tid + 2; ; i++ ){
        UT = xlatcase[T[i]];
        pstate = state;
        state = spfacStateTable[state * 258 + UT];
        if (state == 0){
            if (spfacStateTable[pstate * 258 + 256] == 1){
                nm = atomic_inc(result);
                result[2 * nm + 1] = pstate;
                result[2 * nm + 2] = i;
            }
            break;
        }
    }

    state = 0;
    for( i = 4 * tid + 3; ; i++ ){
        UT = xlatcase[T[i]];
        pstate = state;
        state = spfacStateTable[state * 258 + UT];
        if (state == 0){
            if (spfacStateTable[pstate * 258 + 256] == 1){
                nm = atomic_inc(result);
                result[2 * nm + 1] = pstate;
                result[2 * nm + 2] = i;
            }
            break;
        }
    }
    state = 0;
    for( i = 4 * tid + 4; ; i++ ){
        UT = xlatcase[T[i]];
        pstate = state;
        state = spfacStateTable[state * 258 + UT];
        if (state == 0){
            if (spfacStateTable[pstate * 258 + 256] == 1){
                nm = atomic_inc(result);
                result[2 * nm + 1] = pstate;
                result[2 * nm + 2] = i;
            }
            break;
        }
    }

    state = 0;
    for( i = 4 * tid + 5; ; i++ ){
        UT = xlatcase[T[i]];
        pstate = state;
        state = spfacStateTable[state * 258 + UT];
        if (state == 0){
            if (spfacStateTable[pstate * 258 + 256] == 1){
                nm = atomic_inc(result);
                result[2 * nm + 1] = pstate;
                result[2 * nm + 2] = i;
            }
            break;
        }
    }

    state = 0;
    for( i = 4 * tid + 6; ; i++ ){
        UT = xlatcase[T[i]];
        pstate = state;
        state = spfacStateTable[state * 258 + UT];
        if (state == 0){
            if (spfacStateTable[pstate * 258 + 256] == 1){
                nm = atomic_inc(result);
                result[2 * nm + 1] = pstate;
                result[2 * nm + 2] = i;
            }
            break;
        }
    }

    state = 0;
    for( i = 4 * tid + 7; ; i++ ){
        UT = xlatcase[T[i]];
        pstate = state;
        state = spfacStateTable[state * 258 + UT];
        if (state == 0){
            if (spfacStateTable[pstate * 258 + 256] == 1){
                nm = atomic_inc(result);
                result[2 * nm + 1] = pstate;
                result[2 * nm + 2] = i;
            }
            break;
        }
    }
    
    state = 0;
    for( i = 4 * tid + 8; ; i++ ){
        UT = xlatcase[T[i]];
        pstate = state;
        state = spfacStateTable[state * 258 + UT];
        if (state == 0){
            if (spfacStateTable[pstate * 258 + 256] == 1){
                nm = atomic_inc(result);
                result[2 * nm + 1] = pstate;
                result[2 * nm + 2] = i;
            }
            break;
        }
    }

    state = 0;
    for( i = 4 * tid + 9; ; i++ ){
        UT = xlatcase[T[i]];
        pstate = state;
        state = spfacStateTable[state * 258 + UT];
        if (state == 0){
            if (spfacStateTable[pstate * 258 + 256] == 1){
                nm = atomic_inc(result);
                result[2 * nm + 1] = pstate;
                result[2 * nm + 2] = i;
            }
            break;
        }
    }

    state = 0;
    for( i = 4 * tid + 10; ; i++ ){
        UT = xlatcase[T[i]];
        pstate = state;
        state = spfacStateTable[state * 258 + UT];
        if (state == 0){
            if (spfacStateTable[pstate * 258 + 256] == 1){
                nm = atomic_inc(result);
                result[2 * nm + 1] = pstate;
                result[2 * nm + 2] = i;
            }
            break;
        }
    }

    state = 0;
    for( i = 4 * tid + 11; ; i++ ){
        UT = xlatcase[T[i]];
        pstate = state;
        state = spfacStateTable[state * 258 + UT];
        if (state == 0){
            if (spfacStateTable[pstate * 258 + 256] == 1){
                nm = atomic_inc(result);
                result[2 * nm + 1] = pstate;
                result[2 * nm + 2] = i;
            }
            break;
        }
    }

    state = 0;
    for( i = 4 * tid + 12; ; i++ ){
        UT = xlatcase[T[i]];
        pstate = state;
        state = spfacStateTable[state * 258 + UT];
        if (state == 0){
            if (spfacStateTable[pstate * 258 + 256] == 1){
                nm = atomic_inc(result);
                result[2 * nm + 1] = pstate;
                result[2 * nm + 2] = i;
            }
            break;
        }
    }

    state = 0;
    for( i = 4 * tid + 13; ; i++ ){
        UT = xlatcase[T[i]];
        pstate = state;
        state = spfacStateTable[state * 258 + UT];
        if (state == 0){
            if (spfacStateTable[pstate * 258 + 256] == 1){
                nm = atomic_inc(result);
                result[2 * nm + 1] = pstate;
                result[2 * nm + 2] = i;
            }
            break;
        }
    }

    state = 0;
    for( i = 4 * tid + 14; ; i++ ){
        UT = xlatcase[T[i]];
        pstate = state;
        state = spfacStateTable[state * 258 + UT];
        if (state == 0){
            if (spfacStateTable[pstate * 258 + 256] == 1){
                nm = atomic_inc(result);
                result[2 * nm + 1] = pstate;
                result[2 * nm + 2] = i;
            }
            break;
        }
    }

    state = 0;
    for( i = 4 * tid + 15; ; i++ ){
        UT = xlatcase[T[i]];
        pstate = state;
        state = spfacStateTable[state * 258 + UT];
        if (state == 0){
            if (spfacStateTable[pstate * 258 + 256] == 1){
                nm = atomic_inc(result);
                result[2 * nm + 1] = pstate;
                result[2 * nm + 2] = i;
            }
            break;
        }
    }
    
    state = 0;
    for( i = 4 * tid + 16; ; i++ ){
        UT = xlatcase[T[i]];
        pstate = state;
        state = spfacStateTable[state * 258 + UT];
        if (state == 0){
            if (spfacStateTable[pstate * 258 + 256] == 1){
                nm = atomic_inc(result);
                result[2 * nm + 1] = pstate;
                result[2 * nm + 2] = i;
            }
            break;
        }
    }

    state = 0;
    for( i = 4 * tid + 17; ; i++ ){
        UT = xlatcase[T[i]];
        pstate = state;
        state = spfacStateTable[state * 258 + UT];
        if (state == 0){
            if (spfacStateTable[pstate * 258 + 256] == 1){
                nm = atomic_inc(result);
                result[2 * nm + 1] = pstate;
                result[2 * nm + 2] = i;
            }
            break;
        }
    }

    state = 0;
    for( i = 4 * tid + 18; ; i++ ){
        UT = xlatcase[T[i]];
        pstate = state;
        state = spfacStateTable[state * 258 + UT];
        if (state == 0){
            if (spfacStateTable[pstate * 258 + 256] == 1){
                nm = atomic_inc(result);
                result[2 * nm + 1] = pstate;
                result[2 * nm + 2] = i;
            }
            break;
        }
    }

    state = 0;
    for( i = 4 * tid + 19; ; i++ ){
        UT = xlatcase[T[i]];
        pstate = state;
        state = spfacStateTable[state * 258 + UT];
        if (state == 0){
            if (spfacStateTable[pstate * 258 + 256] == 1){
                nm = atomic_inc(result);
                result[2 * nm + 1] = pstate;
                result[2 * nm + 2] = i;
            }
            break;
        }
    }

    state = 0;
    for( i = 4 * tid + 20; ; i++ ){
        UT = xlatcase[T[i]];
        pstate = state;
        state = spfacStateTable[state * 258 + UT];
        if (state == 0){
            if (spfacStateTable[pstate * 258 + 256] == 1){
                nm = atomic_inc(result);
                result[2 * nm + 1] = pstate;
                result[2 * nm + 2] = i;
            }
            break;
        }
    }

    state = 0;
    for( i = 4 * tid + 21; ; i++ ){
        UT = xlatcase[T[i]];
        pstate = state;
        state = spfacStateTable[state * 258 + UT];
        if (state == 0){
            if (spfacStateTable[pstate * 258 + 256] == 1){
                nm = atomic_inc(result);
                result[2 * nm + 1] = pstate;
                result[2 * nm + 2] = i;
            }
            break;
        }
    }

    state = 0;
    for( i = 4 * tid + 22; ; i++ ){
        UT = xlatcase[T[i]];
        pstate = state;
        state = spfacStateTable[state * 258 + UT];
        if (state == 0){
            if (spfacStateTable[pstate * 258 + 256] == 1){
                nm = atomic_inc(result);
                result[2 * nm + 1] = pstate;
                result[2 * nm + 2] = i;
            }
            break;
        }
    }

    state = 0;
    for( i = 4 * tid + 23; ; i++ ){
        UT = xlatcase[T[i]];
        pstate = state;
        state = spfacStateTable[state * 258 + UT];
        if (state == 0){
            if (spfacStateTable[pstate * 258 + 256] == 1){
                nm = atomic_inc(result);
                result[2 * nm + 1] = pstate;
                result[2 * nm + 2] = i;
            }
            break;
        }
    }

    state = 0;
    for( i = 4 * tid + 24; ; i++ ){
        UT = xlatcase[T[i]];
        pstate = state;
        state = spfacStateTable[state * 258 + UT];
        if (state == 0){
            if (spfacStateTable[pstate * 258 + 256] == 1){
                nm = atomic_inc(result);
                result[2 * nm + 1] = pstate;
                result[2 * nm + 2] = i;
            }
            break;
        }
    }

    state = 0;
    for( i = 4 * tid + 25; ; i++ ){
        UT = xlatcase[T[i]];
        pstate = state;
        state = spfacStateTable[state * 258 + UT];
        if (state == 0){
            if (spfacStateTable[pstate * 258 + 256] == 1){
                nm = atomic_inc(result);
                result[2 * nm + 1] = pstate;
                result[2 * nm + 2] = i;
            }
            break;
        }
    }

    state = 0;
    for( i = 4 * tid + 26; ; i++ ){
        UT = xlatcase[T[i]];
        pstate = state;
        state = spfacStateTable[state * 258 + UT];
        if (state == 0){
            if (spfacStateTable[pstate * 258 + 256] == 1){
                nm = atomic_inc(result);
                result[2 * nm + 1] = pstate;
                result[2 * nm + 2] = i;
            }
            break;
        }
    }

    state = 0;
    for( i = 4 * tid + 27; ; i++ ){
        UT = xlatcase[T[i]];
        pstate = state;
        state = spfacStateTable[state * 258 + UT];
        if (state == 0){
            if (spfacStateTable[pstate * 258 + 256] == 1){
                nm = atomic_inc(result);
                result[2 * nm + 1] = pstate;
                result[2 * nm + 2] = i;
            }
            break;
        }
    }

    state = 0;
    for( i = 4 * tid + 28; ; i++ ){
        UT = xlatcase[T[i]];
        pstate = state;
        state = spfacStateTable[state * 258 + UT];
        if (state == 0){
            if (spfacStateTable[pstate * 258 + 256] == 1){
                nm = atomic_inc(result);
                result[2 * nm + 1] = pstate;
                result[2 * nm + 2] = i;
            }
            break;
        }
    }

    state = 0;
    for( i = 4 * tid + 29; ; i++ ){
        UT = xlatcase[T[i]];
        pstate = state;
        state = spfacStateTable[state * 258 + UT];
        if (state == 0){
            if (spfacStateTable[pstate * 258 + 256] == 1){
                nm = atomic_inc(result);
                result[2 * nm + 1] = pstate;
                result[2 * nm + 2] = i;
            }
            break;
        }
    }

    state = 0;
    for( i = 4 * tid + 30; ; i++ ){
        UT = xlatcase[T[i]];
        pstate = state;
        state = spfacStateTable[state * 258 + UT];
        if (state == 0){
            if (spfacStateTable[pstate * 258 + 256] == 1){
                nm = atomic_inc(result);
                result[2 * nm + 1] = pstate;
                result[2 * nm + 2] = i;
            }
            break;
        }
    }

    state = 0;
    for( i = 4 * tid + 31; ; i++ ){
        UT = xlatcase[T[i]];
        pstate = state;
        state = spfacStateTable[state * 258 + UT];
        if (state == 0){
            if (spfacStateTable[pstate * 258 + 256] == 1){
                nm = atomic_inc(result);
                result[2 * nm + 1] = pstate;
                result[2 * nm + 2] = i;
            }
            break;
        }
    }





}


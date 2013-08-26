
/*
 **   SPFAC.H 
 **
 **
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sf_types.h"

#include "alvincl.h"

#ifndef SPFAC_H
#define SPFAC_H

/*
 *   Prototypes
 */


#define SPFAC_ALPHABET_SIZE 256

#define SPFAC_FAIL_STATE    0

#define MEM_ALIGNMENT		256
#define MAX_PKT_CACHE_SIZE  10485760   //1M
#define NUM_RNODE           2

/*
 *  Ring
*/
typedef struct _rnode {
    cl_mem cache;
    cl_mem result;
    unsigned char *p_cache;
    int *p_result;
    int c_count;
    cl_event kernel_event;
    struct _rnode *next;
} RNODE;

typedef struct _spfac_userdata{
    uint32_t ref_count;
    void *id;

} SPFAC_USERDATA;

typedef struct _spfac_pattern{
    struct _spfac_pattern *next;
    unsigned char *patrn;
    unsigned char *casepatrn;
    int n;
    int nocase;
    int offset;
    int depth;
    int negative;
    SPFAC_USERDATA *udata;
    int iid;
    void *rule_option_tree;
    void *neg_list;
} SPFAC_PATTERN;

/*
 * State machine Struct
 */
typedef struct{
    int spfacMaxStates;  
    int spfacNumStates;  

    SPFAC_PATTERN *spfacPatterns;
    int *spfacStateTable;
    cl_mem mem_object;
    RNODE *acl_ring;
    RNODE *p_ring_cpu;
    RNODE *p_ring_gpu;
    SPFAC_PATTERN **MatchList;

    int numPatterns;
    void (*userfree)(void *p);
    void (*optiontreefree)(void **p);
    void (*neg_list_free)(void **p);
}SPFAC_STRUCT;

/*
 *   Prototypes
 */
SPFAC_STRUCT * spfacNew (void (*userfree)(void *p),
        void (*optiontreefree)(void **p),
        void (*neg_list_free)(void **p));

int spfacAddPattern( SPFAC_STRUCT * p, unsigned char * pat, int n,
        int nocase, int offset, int depth, int negative, void * id, int iid );

int spfacCompile ( SPFAC_STRUCT * spfac,
        int (*build_tree)(void * id, void **existing_tree),
        int (*neg_list_func)(void *id, void **list));

int spfacSearch ( SPFAC_STRUCT * spfac,unsigned char * T, int n, 
        int (*Match)(void * id, void *tree, int index, void *data, void *neg_list),
        void * data, int* current_state );

void spfacFree ( SPFAC_STRUCT * spfac );
int spfacPatternCount ( SPFAC_STRUCT * spfac );

int spfacPrintDetailInfo(SPFAC_STRUCT *);

int spfacPrintSummaryInfo(void);

#endif


/*
**   SPFAC.H 
**
**
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sf_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef SPFAC_H
#define SPFAC_H

/*
*   Prototypes
*/


#define SPFAC_ALPHABET_SIZE    256          

#define SPFAC_FAIL_STATE   -1     

typedef struct _spfac_userdata
{
    uint32_t ref_count;
    void *id;

} SPFAC_USERDATA;

typedef struct _spfac_pattern {      

    struct  _spfac_pattern *next;
    unsigned char         *patrn;
    unsigned char         *casepatrn;
    int      n;
    int      nocase;
    int      offset;
    int      depth;
    int      negative;
    SPFAC_USERDATA *udata;
    int      iid;
    void   * rule_option_tree;
    void   * neg_list;

} SPFAC_PATTERN;


typedef struct  {    

    /* Next state - based on input character */
    int      NextState[ SPFAC_ALPHABET_SIZE ];  

    /* Failure state - used while building NFA & DFA  */
    int      FailState;   

    /* List of patterns that end here, if any */
    SPFAC_PATTERN *MatchList;   

}SPFAC_STATETABLE; 


/*
* State machine Struct
*/
typedef struct {
  
    int spfacMaxStates;  
    int spfacNumStates;  

    SPFAC_PATTERN    * spfacPatterns;
    SPFAC_STATETABLE * spfacStateTable;

    int   bcSize;
    short bcShift[256];

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

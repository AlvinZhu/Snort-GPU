/*
 **
 **
 **
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "spfac.h"
#include "util.h"
#include "snort_debug.h"

#include "alvincl.h"

#define MEM_ALIGNMENT			256
#define DEVICE_TYPE				CL_DEVICE_TYPE_GPU

#define MAX_PKT_CACHE_SIZE 10485760   //10M

#ifdef DEBUG_SPFAC
static int max_memory = 0;
#endif

struct _k_arg_struct {
    int state;
    int n;
    unsigned char T[15728640];
};

typedef struct _k_arg_struct k_arg_struct;



static alvincl_struct * acls = NULL;

static void* spfacMalloc(size_t n){
    void *p = NULL;
    p = calloc((size_t)1, n);
#ifdef DEBUG_SPFAC
    if (p != NULL)
        max_memory += n;
#endif
    if (p == NULL){
        fprintf(stderr, "spfacMalloc error!");
        exit(0);
    }
    return p;
}

static void spfacUnMalloc(void *p){
    if (p != NULL)
        free (p);
}

/*
 ** Case Translation Table
 */
static unsigned char xlatcase[256];

/*
 *
 */
    static void
init_xlatcase ()
{
    int i;
    for (i = 0; i < 256; i++)
    {
        xlatcase[i] = (unsigned char)toupper (i);
    }
}


/*
 *
 */
    static inline void
ConvertCaseEx (unsigned char *d, unsigned char *s, int m)
{
    int i;
    for (i = 0; i < m; i++)
    {
        d[i] = xlatcase[s[i]];
    }
}


static void alvinclInit(){
    cl_int ret_num;
    int * result;
    unsigned char *clxlatcase = xlatcase;
    cl_event t_map_event;
    cl_event t_unmap_event;


    if(acls == NULL){
        acls = (alvincl_struct*)spfacMalloc(sizeof(alvincl_struct));
        getPlatforms(acls);
        getDevices(acls);
        setDevice(acls, DEVICE_TYPE);
        createContext(acls);
        createProgram(acls, "kernel.cl");
        acls->platforms[acls->pdex].kernel = clCreateKernel(acls->platforms[acls->pdex].program, "spfac_kernel_1", &ret_num);
        checkResult(acls, ret_num, "clCreateKernel");
        createCommandQueue(acls, CL_QUEUE_PROFILING_ENABLE);

        initMemoryObjects(acls, 3);
        acls->platforms[acls->pdex].mem_objects[0] = clCreateBuffer(acls->platforms[acls->pdex].context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, SPFAC_ALPHABET_SIZE * sizeof(unsigned char), clxlatcase, &ret_num);
        checkResult(acls, ret_num, "clCreateBuffer(xlatcase)");
        acls->platforms[acls->pdex].mem_objects[1] = clCreateBuffer(acls->platforms[acls->pdex].context, CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, sizeof(k_arg_struct), NULL, &ret_num);
        checkResult(acls, ret_num, "clCreateBuffer(T)");
        acls->platforms[acls->pdex].mem_objects[2] = clCreateBuffer(acls->platforms[acls->pdex].context, CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR, 2 * sizeof(k_arg_struct) * sizeof(int), NULL, &ret_num);
        checkResult(acls, ret_num, "clCreateBuffer(result)");

        result = clEnqueueMapBuffer(acls->platforms[acls->pdex].devices[acls->ddex].command_queue, acls->platforms[acls->pdex].mem_objects[2], CL_TRUE, CL_MAP_WRITE_INVALIDATE_REGION, 0, 2 * sizeof(k_arg_struct) * sizeof(int), 0, NULL, &t_map_event, &ret_num);
        checkResult(acls, ret_num, "clEnqueueMapBuffer(mem_objects[2])");
        while(clWaitForEvents(1, &t_map_event) != CL_SUCCESS){
        }

        memset (result, 0, 2 * sizeof(k_arg_struct) * sizeof(int));

        ret_num = clEnqueueUnmapMemObject(acls->platforms[acls->pdex].devices[acls->ddex].command_queue, acls->platforms[acls->pdex].mem_objects[2], result, 0, NULL, &t_unmap_event);
        checkResult(acls, ret_num, "clEnqueueUnmapBuffer(mem_objects[2])");
        while(clWaitForEvents(1, &t_unmap_event) != CL_SUCCESS){
        }


        ret_num = clSetKernelArg(acls->platforms[acls->pdex].kernel, 0, sizeof(cl_mem), &(acls->platforms[acls->pdex].mem_objects[0]));
        checkResult(acls, ret_num, "clSetKernelArg(0)");
        ret_num = clSetKernelArg(acls->platforms[acls->pdex].kernel, 1, sizeof(cl_mem), &(acls->platforms[acls->pdex].mem_objects[1]));
        checkResult(acls, ret_num, "clSetKernelArg(1)");
        ret_num = clSetKernelArg(acls->platforms[acls->pdex].kernel, 2, sizeof(cl_mem), &(acls->platforms[acls->pdex].mem_objects[2]));
        checkResult(acls, ret_num, "clSetKernelArg(2)");
    }
}

static void alvinclFree(){
    if (acls != NULL){
        cleanUp(acls);
        spfacUnMalloc((void*)acls);
        acls = NULL;
    }
}


/*
*    Simple QUEUE NODE
*/
typedef struct _qnode
{
  int state;
   struct _qnode *next;
}
QNODE;

/*
*    Simple QUEUE Structure
*/
typedef struct _queue
{
  QNODE * head, *tail;
  int count;
}
QUEUE;

/*
*
*/
static void
queue_init (QUEUE * s)
{
  s->head = s->tail = 0;
  s->count = 0;
}

/*
*  Add Tail Item to queue
*/
static void
queue_add (QUEUE * s, int state)
{
  QNODE * q;
  if (!s->head)
    {
      q = s->tail = s->head = (QNODE *) spfacMalloc (sizeof (QNODE));
      q->state = state;
      q->next = 0;
    }
  else
    {
      q = (QNODE *) spfacMalloc (sizeof (QNODE));
      q->state = state;
      q->next = 0;
      s->tail->next = q;
      s->tail = q;
    }
  s->count++;
}



/*
*  Remove Head Item from queue
*/
static int
queue_remove (QUEUE * s)
{
  int state = 0;
  QNODE * q;
  if (s->head)
    {
      q = s->head;
      state = q->state;
      s->head = s->head->next;
      s->count--;
      if (!s->head)
      {
          s->tail = 0;
          s->count = 0;
      }
    spfacUnMalloc(q);
    }
  return state;
}


/*
*
*/
static int
queue_count (QUEUE * s)
{
  return s->count;
}


/*
*
*/
static void
queue_free (QUEUE * s)
{
  while (queue_count (s))
    {
      queue_remove (s);
    }
}



/*
 *  Add a pattern to the list of patterns terminated at this state.
 *  Insert at front of list.
 */
    static void
AddMatchListEntry (SPFAC_STRUCT * spfac, int state, SPFAC_PATTERN * px)
{
    SPFAC_PATTERN * p;
    p = (SPFAC_PATTERN *) spfacMalloc (sizeof (SPFAC_PATTERN));
    memcpy (p, px, sizeof (SPFAC_PATTERN));
    p->next = spfac->MatchList[state];
    spfac->MatchList[state] = p;
    spfac->spfacStateTable[state * (SPFAC_ALPHABET_SIZE + 2) + 256] = 1;
}

/*
*
*/
static SPFAC_PATTERN *
CopyMatchListEntry (SPFAC_PATTERN * px)
{
  SPFAC_PATTERN * p;
  p = (SPFAC_PATTERN *) spfacMalloc (sizeof (SPFAC_PATTERN));
  memcpy (p, px, sizeof (SPFAC_PATTERN));
  px->udata->ref_count++;
  p->next = 0;
  return p;
}



/*
   Add Pattern States
   */
    static void
AddPatternStates (SPFAC_STRUCT * spfac, SPFAC_PATTERN * p)
{
    unsigned char *pattern;
    int state=0, next, n;
    n = p->n;
    pattern = p->patrn;

    /*
     *  Match up pattern with existing states
     */
    for (; n > 0; pattern++, n--)
    {
        next = spfac->spfacStateTable[state * (SPFAC_ALPHABET_SIZE + 2) + *pattern];
        if (next == SPFAC_FAIL_STATE)
            break;
        state = next;
    }

    /*
     *   Add new states for the rest of the pattern bytes, 1 state per byte
     */
    for (; n > 0; pattern++, n--)
    {
        spfac->spfacNumStates++;
        spfac->spfacStateTable[state * (SPFAC_ALPHABET_SIZE + 2) + *pattern] 
            = spfac->spfacNumStates;
        state = spfac->spfacNumStates;
    }
    
    AddMatchListEntry (spfac, state, p);
}



/*
 *
 */
SPFAC_STRUCT * spfacNew (void (*userfree)(void *p),
        void (*optiontreefree)(void **p),
        void (*neg_list_free)(void **p))
{
    SPFAC_STRUCT * p;
    init_xlatcase ();
    alvinclInit();
    p = (SPFAC_STRUCT *) spfacMalloc (sizeof (SPFAC_STRUCT));
    memset (p, 0, sizeof (SPFAC_STRUCT));
    p->userfree              = userfree;
    p->optiontreefree        = optiontreefree;
    p->neg_list_free         = neg_list_free;
    return p;
}


/*
 *   Add a pattern to the list of patterns for this state machine
 */
    int
spfacAddPattern (SPFAC_STRUCT * p, unsigned char *pat, int n, int nocase,
        int offset, int depth, int negative, void * id, int iid)
{
    SPFAC_PATTERN * plist;
    plist = (SPFAC_PATTERN *) spfacMalloc (sizeof (SPFAC_PATTERN));
    plist->patrn = (unsigned char *) spfacMalloc (n);
    ConvertCaseEx (plist->patrn, pat, n);
    plist->casepatrn = (unsigned char *) spfacMalloc (n);
    memcpy (plist->casepatrn, pat, n);

    plist->udata = (SPFAC_USERDATA *)spfacMalloc(sizeof(SPFAC_USERDATA));
    plist->udata->ref_count = 1;
    plist->udata->id = id;

    plist->n = n;
    plist->nocase = nocase;
    plist->negative = negative;
    plist->offset = offset;
    plist->depth = depth;
    plist->iid = iid;
    plist->next = p->spfacPatterns;
    p->spfacPatterns = plist;
    p->numPatterns++;
    return 0;
}

static int spfacBuildMatchStateTrees( SPFAC_STRUCT * spfac,
        int (*build_tree)(void * id, void **existing_tree),
        int (*neg_list_func)(void *id, void **list) )
{
    int i, cnt = 0;
    SPFAC_PATTERN * mlist;

    /* Find the states that have a MatchList */
    for (i = 0; i < spfac->spfacMaxStates; i++)
    {
        for ( mlist=spfac->MatchList[i];
                mlist!=NULL;
                mlist=mlist->next )
        {
            if (mlist->udata->id)
            {
                if (mlist->negative)
                {
                    neg_list_func(mlist->udata->id, &spfac->MatchList[i]->neg_list);
                }
                else
                {
                    build_tree(mlist->udata->id, &spfac->MatchList[i]->rule_option_tree);
                }
            }

            cnt++;
        }

        if (spfac->MatchList[i])
        {
            /* Last call to finalize the tree */
            build_tree(NULL, &spfac->MatchList[i]->rule_option_tree);
        }
    }

    return cnt;
}


/*
 *   Compile State Machine
 */
    int
spfacCompile (SPFAC_STRUCT * spfac,
        int (*build_tree)(void * id, void **existing_tree),
        int (*neg_list_func)(void *id, void **list))
{
    int i, k;
    int r, s;
    QUEUE q, *queue = &q;
    SPFAC_PATTERN * plist;
    SPFAC_PATTERN * px;

    cl_int ret_num;

    /* Init a Queue */
    queue_init (queue);



    /* Count number of states */
    spfac->spfacMaxStates = 1;
    for (plist = spfac->spfacPatterns; plist != NULL; plist = plist->next)
    {
        spfac->spfacMaxStates += plist->n;
    }
    //spfac->spfacStateTable = (unsigned int*) spfacMalloc (sizeof (unsigned int) * (SPFAC_ALPHABET_SIZE + 2) * spfac->spfacMaxStates);
    ret_num = posix_memalign((void**)&(spfac->spfacStateTable), MEM_ALIGNMENT, sizeof (int) * (SPFAC_ALPHABET_SIZE + 2) * spfac->spfacMaxStates);
    checkPointer(acls, spfac->spfacStateTable, "spfac->spfacStateTable");
    memset (spfac->spfacStateTable, 0,
            sizeof (int) * (SPFAC_ALPHABET_SIZE + 2) * spfac->spfacMaxStates);
    spfac->MatchList =
        (SPFAC_PATTERN**) spfacMalloc (sizeof(SPFAC_PATTERN*) * spfac->spfacMaxStates);
    memset (spfac->MatchList, 0, sizeof(SPFAC_PATTERN*) * spfac->spfacMaxStates);

    /* Initialize state zero as a branch */
    spfac->spfacNumStates = 0;

    /* Initialize all States NextStates to FAILED */
    for (k = 0; k < spfac->spfacMaxStates; k++)
    {
        for (i = 0; i < SPFAC_ALPHABET_SIZE + 2; i++)
        {
            spfac->spfacStateTable[k * (SPFAC_ALPHABET_SIZE + 2) + i] = SPFAC_FAIL_STATE;
        }
    }

    /* Add each Pattern to the State Table */
    for (plist = spfac->spfacPatterns; plist != NULL; plist = plist->next)
    {
        AddPatternStates (spfac, plist);
    }

    /* Add Pattern's Pattern to it's MatchList */
    for (k = 0; k < spfac->spfacMaxStates; k++){
        if(spfac->MatchList[k] != NULL){
            queue_add(queue, k);
            plist = spfac->MatchList[k];
            while(plist->next != NULL)
                plist = plist->next;
            while(queue_count (queue) > 0){
                r = queue_remove (queue);
                for(i = 0; i < SPFAC_ALPHABET_SIZE; i++){
                    if((s = spfac->spfacStateTable[r * 258 + i]) != 0){
                        queue_add (queue, s);
                        if(spfac->MatchList[s] != NULL){
                            px = CopyMatchListEntry (plist);
                            px->next = spfac->MatchList[s];
                            spfac->MatchList[s] = px;
                        }
                    }
                }
            }
        }
    }

    /* */
    if (build_tree && neg_list_func)
    {
        spfacBuildMatchStateTrees(spfac, build_tree, neg_list_func);
    }
    spfac->mem_object = (void*)clCreateBuffer(acls->platforms[acls->pdex].context, CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, sizeof (int) * (SPFAC_ALPHABET_SIZE + 2) * spfac->spfacMaxStates, spfac->spfacStateTable, &ret_num);
    checkResult(acls, ret_num, "clCreateBuffer(spfac->mem_object)");

    /* Clean up the queue */
    queue_free (queue);


    return 0;
}


//static unsigned char Tc[64*1024];

/*
 *   Search Text or Binary Data for Pattern matches
 */
    int
spfacSearch (SPFAC_STRUCT * spfac, unsigned char *Tx, int n,
        int (*Match)(void * id, void *tree, int index, void *data, void *neg_list),
        void *data, int* current_state )
{
    //int state = 0;
    SPFAC_PATTERN * mlist;
    //unsigned char *Tend;
    //int * StateTable = spfac->spfacStateTable;
    int nfound = 0;
    SPFAC_PATTERN ** MatchList = spfac->MatchList;
    k_arg_struct *kas;
    int n_cl = (n%384)?(n / 384 + 1):(n / 384);
    int * result;
    int * presult;
    int index;
    size_t global_work_group_size[1] = { 384 };
    size_t local_work_group_size[1] = { 64 };


    cl_event t_map_event;
    cl_event t_unmap_event;
    cl_event kernel_event;

    cl_int ret_num;
    //
    kas = clEnqueueMapBuffer(acls->platforms[acls->pdex].devices[acls->ddex].command_queue, acls->platforms[acls->pdex].mem_objects[1], CL_TRUE, CL_MAP_WRITE_INVALIDATE_REGION, 0, (n_cl * 384 + 8) * sizeof(unsigned char), 0, NULL, &t_map_event, &ret_num);
    checkResult(acls, ret_num, "clEnqueueMapBuffer(mem_objects[1])");
    while(clWaitForEvents(1, &t_map_event) != CL_SUCCESS){
    }

    memcpy((kas->T), Tx, n * sizeof(unsigned char));
    memset ((kas->T + n * sizeof(unsigned char)), 0, n_cl * 384 - n);

    kas->state = *current_state;
    kas->n = n_cl;

    ret_num = clEnqueueUnmapMemObject(acls->platforms[acls->pdex].devices[acls->ddex].command_queue, acls->platforms[acls->pdex].mem_objects[1], kas, 0, NULL, &t_unmap_event);
    checkResult(acls, ret_num, "clEnqueueUnmapBuffer(mem_objects[1])");
    while(clWaitForEvents(1, &t_unmap_event) != CL_SUCCESS){
    }

    //
    ret_num = clSetKernelArg(acls->platforms[acls->pdex].kernel, 3, sizeof(cl_mem), &(spfac->mem_object));
    checkResult(acls, ret_num, "clSetKernelArg(3)");

    //
    ret_num = clEnqueueNDRangeKernel(acls->platforms[acls->pdex].devices[acls->ddex].command_queue, acls->platforms[acls->pdex].kernel, 1, NULL, global_work_group_size, local_work_group_size, 0, NULL, &kernel_event);
    checkResult(acls, ret_num, "clEnqueueNDRangeKernel");
    while(clWaitForEvents(1, &kernel_event) != CL_SUCCESS){
    }

    //
    result = clEnqueueMapBuffer(acls->platforms[acls->pdex].devices[acls->ddex].command_queue, acls->platforms[acls->pdex].mem_objects[2], CL_TRUE, CL_MAP_WRITE, 0, (n * 2 + 1) * sizeof(int), 0, NULL, &t_map_event, &ret_num);
    checkResult(acls, ret_num, "clEnqueueMapBuffer(mem_objects[2])");
    while(clWaitForEvents(1, &t_map_event) != CL_SUCCESS){
    }
    //
    //printf("m:%d\t", *result);
    presult = result + 1;
    while ((*result) != 0){
        mlist = MatchList[(*presult)];
        presult++;
        index = (*presult) - mlist->n + 1;
        while(mlist != NULL){
            nfound++;
            if (Match (mlist->udata->id, mlist->rule_option_tree, index, data, mlist->neg_list) > 0)
            {
                return nfound;
            }
            mlist = mlist->next;
        }
        presult++;
        (*result)--;
    }
    //
    ret_num = clEnqueueUnmapMemObject(acls->platforms[acls->pdex].devices[acls->ddex].command_queue, acls->platforms[acls->pdex].mem_objects[2], result, 0, NULL, &t_unmap_event);
    checkResult(acls, ret_num, "clEnqueueUnmapBuffer(mem_objects[2])");
    while(clWaitForEvents(1, &t_unmap_event) != CL_SUCCESS){
    }

    return nfound;
}


/*
 *   Free all memory
 */
    void
spfacFree (SPFAC_STRUCT * spfac)
{
    int i;
    SPFAC_PATTERN * mlist, *ilist;
    for (i = 0; i < spfac->spfacMaxStates; i++)
    {
        mlist = spfac->MatchList[i];
        while (mlist)
        {
            ilist = mlist;
            mlist = mlist->next;

            ilist->udata->ref_count--;
            if (ilist->udata->ref_count == 0)
            {
                if (spfac->userfree && ilist->udata->id)
                    spfac->userfree(ilist->udata->id);

                spfacUnMalloc(ilist->udata);
            }

            if (ilist->rule_option_tree && spfac->optiontreefree)
            {
                spfac->optiontreefree(&(ilist->rule_option_tree));
            }

            if (ilist->neg_list && spfac->neg_list_free)
            {
                spfac->neg_list_free(&(ilist->neg_list));
            }

            spfacUnMalloc(ilist);
        }
    }
    spfacUnMalloc(spfac->MatchList);
    spfacUnMalloc(spfac->spfacStateTable);
    mlist = spfac->spfacPatterns;
    while(mlist)
    {
        ilist = mlist;
        mlist = mlist->next;
        spfacUnMalloc(ilist->patrn);
        spfacUnMalloc(ilist->casepatrn);
        spfacUnMalloc(ilist);
    }
    if(spfac->mem_object != 0)
        clReleaseMemObject(spfac->mem_object);
    spfacUnMalloc (spfac);
    alvinclFree();
}

int spfacPatternCount ( SPFAC_STRUCT * spfac )
{
    return spfac->numPatterns;
}

/*
 *
 */
static void Print_DFA( SPFAC_STRUCT * spfac )
{
    int k;
    int i;
    int next;
    int mc;
    SPFAC_PATTERN * mlist=0;

    for (k = 0; k < spfac->spfacMaxStates; k++)
    {
        printf("%d\t", k);
        for (i = 0; i < SPFAC_ALPHABET_SIZE + 2; i++)
        {
            next = spfac->spfacStateTable[k * 258 + i];

            if( next !=  SPFAC_FAIL_STATE )
            {
                if( isprint(i) )
                    printf("%3c->%-5d\t",i,next);
                else{
                    if(i == 256){
                        mlist = spfac->MatchList[k];
                        mc = 0;
                        while(mlist != NULL){
                            mc++;
                            mlist = mlist->next;
                        }
                        printf("Match:%d\t", mc);
                    }
                    else
                        printf("%3d->%-5d\t",i,next);
                }
            }
        }
        printf("\n");
    }

}


int spfacPrintDetailInfo(SPFAC_STRUCT * p)
{
    if(p)
        p = p;
    return 0;
}

int spfacPrintSummaryInfo(void)
{
#ifdef XXXXX
    char * fsa[]={
        "TRIE",
        "NFA",
        "DFA",
    };

    SPFAC_STRUCT2 * p = &summary.spfac;

    if( !summary.num_states )
        return;

    LogMessage("+--[Pattern Matcher:Aho-Corasick Summary]----------------------\n");
    LogMessage("| Alphabet Size    : %d Chars\n",p->spfacAlphabetSize);
    LogMessage("| Sizeof State     : %d bytes\n",sizeof(acstate_t));
    LogMessage("| Storage Format   : %s \n",sf[ p->spfacFormat ]);
    LogMessage("| Num States       : %d\n",summary.num_states);
    LogMessage("| Num Transitions  : %d\n",summary.num_transitions);
    LogMessage("| State Density    : %.1f%%\n",100.0*(double)summary.num_transitions/(summary.num_states*p->spfacAlphabetSize));
    LogMessage("| Finite Automatum : %s\n", fsa[p->spfacFSA]);
    if( max_memory < 1024*1024 )
        LogMessage("| Memory           : %.2fKbytes\n", (float)max_memory/1024 );
    else
        LogMessage("| Memory           : %.2fMbytes\n", (float)max_memory/(1024*1024) );
    LogMessage("+-------------------------------------------------------------\n");

#endif
    return 0;
}

//#define SPFAC_MAIN
#ifdef SPFAC_MAIN

/*
 *  Text Data Buffer
 */
unsigned char text[512];

/*
 *    A Match is found
 */
    int
MatchFound (void * id, void *tree, int index, void *data, void *neg_list)
{
    fprintf (stdout, "%s\n", (char *) id);
    return 0;
}

/*
 *
 */
int main(){
    SPFAC_STRUCT * spfac;
    char *text1;
    char *text2;
    char *p = "CCCCC";
    int nocase = 1;
    int current_state = 0;

    cl_ulong start, end, use;
    double band_width;

    int ret_num;
    int i, j;
    int *pcs, cs[] = {MAX_PKT_CACHE_SIZE, 1024 * 1024, 1024 * 128, 10240, 1536, 0};

    spfac = spfacNew (NULL, NULL, NULL);

    spfacAddPattern (spfac, p, strlen (p), nocase, 0, 0, 0, (void*)p, 0);

    spfacCompile (spfac, NULL, NULL);

    //Print_DFA(spfac);
    ret_num = posix_memalign((void**)&(text1), MEM_ALIGNMENT, sizeof (char) * MAX_PKT_CACHE_SIZE);
    checkPointer(acls, text1, "text1");
    memset (text1, 'A', sizeof (char) * MAX_PKT_CACHE_SIZE);

    ret_num = posix_memalign((void**)&(text2), MEM_ALIGNMENT, sizeof (char) * MAX_PKT_CACHE_SIZE);
    checkPointer(acls, text2, "text2");
    memset (text2, 'B', sizeof (char) * MAX_PKT_CACHE_SIZE);
    
    j = cs[0];
    pcs = cs;
    while( j > 0 ){

        //printf("j=%d \n", j);
        start = timeNanos();
        for(i = 0; i < (MAX_PKT_CACHE_SIZE / j * 5); i++){
            spfacSearch (spfac, text1, sizeof (char) * j, MatchFound, NULL, &current_state);
            spfacSearch (spfac, text2, sizeof (char) * j, MatchFound, NULL, &current_state);
            //printf("%d\n", i);
        }
        end = timeNanos();

        use = end - start;
        //printf("%ld \n", use);
        //band_width = use / 1000000000;
        //printf("%f \n", band_width);
        band_width = 100.0 * 8 / use / 1024 * 1000000000;
        printf("Cache size:%8d Byte\tBandwidth:%f Gb/s\n", j, band_width);

        pcs++;
        j = *pcs;
    }

    spfacFree (spfac);

    return 0;
}

    int
Tmain (int argc, char **argv)
{
    int i, nocase = 0;
    SPFAC_STRUCT * spfac;
    char * p;
    int current_state = 0;
    if (argc < 3)

    {
        fprintf (stderr,
                "Usage: snort text pattern-1 [word-1] [word-2] ... [word-n] [-nocase]\n");
        exit (0);
    }
    spfac = spfacNew (NULL, NULL, NULL);
    strcpy ((char *)text, argv[1]);
    for (i = 1; i < argc; i++)
        if (strcmp (argv[i], "-nocase") == 0)
            nocase = 1;
    for (i = 2; i < argc; i++)

    {
        if (argv[i][0] == '-')
            continue;
        p = argv[i];

        spfacAddPattern (spfac, p, strlen (p), nocase, 0, 0, 0,
                (void*)p, i - 2);
    }
    spfacCompile (spfac, NULL, NULL);
    //Print_DFA(spfac);
    spfacSearch (spfac, text, strlen (text), MatchFound, NULL, &current_state);
    spfacFree (spfac);
    //printf ("normal pgm end\n");
    return (0);
}
#endif /*  */


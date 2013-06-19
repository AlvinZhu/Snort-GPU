/*
 **     Secure Parallel Failureless-AC Alogithm
 **     Multi-Pattern Search Engine
 **
 **     Author: Alvin Zhu (alvin.zhuge@gmail.com)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>

#include <time.h>
#include "alvincl.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "spfac.h"
#include "util.h"
#include "snort_debug.h"

#define MEM_ALIGNMENT			256
//#define DEVICE_TYPE				CL_DEVICE_TYPE_GPU
static cl_device_type DEVICE_TYPE = CL_DEVICE_TYPE_GPU;
static int KERNEL_ID = 1;

#define MAX_PKT_CACHE_SIZE 10485760   //10M

#ifdef DEBUG_SPFAC
static int max_memory = 0;
#endif

static acl_struct * acls = NULL;

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
static unsigned char xlatcase[SPFAC_ALPHABET_SIZE];

/*
 *
 */
    static void
init_xlatcase ()
{
    int i;
    for (i = 0; i < SPFAC_ALPHABET_SIZE; i++)
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


static void alvinclInit()
{
    cl_int ret_num;
    int * result;
    unsigned char *clxlatcase = xlatcase;

    if(acls == NULL){
        acls = (acl_struct*)spfacMalloc(sizeof(acl_struct));
        aclGetPlatforms(acls);
        aclGetDevices(acls);
        aclSetDevice(acls, DEVICE_TYPE);
        aclCreateContext(acls);
        aclCreateProgram(acls, "kernel.cl");
        
        char kernelname[1024];
        sprintf(kernelname, "spfac_kernel_%d", KERNEL_ID);
        aclCreateKernel(acls, kernelname);

        aclCreateCommandQueue(acls, CL_QUEUE_PROFILING_ENABLE);
        aclInitMemoryObjects(acls, 2);
        //
        if (strcmp(acls->platform->name, "AMD Accelerated Parallel Processing") == 0){
            //printf("AMD\n");
            acls->platform->mem_objects[0] = clCreateBuffer(acls->platform->context,
                    CL_MEM_READ_ONLY | CL_MEM_USE_PERSISTENT_MEM_AMD, 
                    SPFAC_ALPHABET_SIZE * sizeof(unsigned char), NULL, &ret_num);
            aclCheckResult(acls, ret_num, "clCreateBuffer(xlatcase)");

            acls->platform->mem_objects[1] = clCreateBuffer(acls->platform->context,
                    CL_MEM_READ_WRITE | CL_MEM_USE_PERSISTENT_MEM_AMD, 
                    (2 * MAX_PKT_CACHE_SIZE + 1) * sizeof(int), NULL, &ret_num);
            aclCheckResult(acls, ret_num, "clCreateBuffer(result)");

            clxlatcase = clEnqueueMapBuffer(acls->device->command_queue,
                    acls->platform->mem_objects[0],
                    CL_TRUE, CL_MAP_WRITE_INVALIDATE_REGION, 0,
                    SPFAC_ALPHABET_SIZE * sizeof(unsigned char), 0, NULL, NULL, &ret_num);
            aclCheckResult(acls, ret_num, "clEnqueueMapBuffer(mem_objects[0])");

            memcpy(clxlatcase, xlatcase, SPFAC_ALPHABET_SIZE * sizeof(unsigned char));

            ret_num = clEnqueueUnmapMemObject(acls->device->command_queue,
                    acls->platform->mem_objects[0], clxlatcase, 0, NULL, NULL);
            aclCheckResult(acls, ret_num, "clEnqueueUnmapBuffer(mem_objects[0])");

            result = clEnqueueMapBuffer(acls->device->command_queue,
                    acls->platform->mem_objects[1],
                    CL_TRUE, CL_MAP_WRITE_INVALIDATE_REGION, 0,
                    (2 * MAX_PKT_CACHE_SIZE + 1) * sizeof(int), 0, NULL, NULL, &ret_num);
            aclCheckResult(acls, ret_num, "clEnqueueMapBuffer(mem_objects[1])");

            memset (result, 0, (2 * MAX_PKT_CACHE_SIZE + 1) * sizeof(int));

            ret_num = clEnqueueUnmapMemObject(acls->device->command_queue,
                    acls->platform->mem_objects[1], result, 0, NULL, NULL);
            aclCheckResult(acls, ret_num, "clEnqueueUnmapBuffer(mem_objects[1])");
        } else {
            acls->platform->mem_objects[0] = clCreateBuffer(acls->platform->context,
                    CL_MEM_READ_ONLY, 
                    SPFAC_ALPHABET_SIZE * sizeof(unsigned char), NULL, &ret_num);
            aclCheckResult(acls, ret_num, "clCreateBuffer(xlatcase)");

            acls->platform->mem_objects[1] = clCreateBuffer(acls->platform->context,
                    CL_MEM_READ_WRITE, 
                    (2 * MAX_PKT_CACHE_SIZE + 1) * sizeof(int), NULL, &ret_num);
            aclCheckResult(acls, ret_num, "clCreateBuffer(result)");

            clxlatcase = clEnqueueMapBuffer(acls->device->command_queue,
                    acls->platform->mem_objects[0],
                    CL_TRUE, CL_MAP_WRITE, 0,
                    SPFAC_ALPHABET_SIZE * sizeof(unsigned char), 0, NULL, NULL, &ret_num);
            aclCheckResult(acls, ret_num, "clEnqueueMapBuffer(mem_objects[0])");

            memcpy(clxlatcase, xlatcase, SPFAC_ALPHABET_SIZE * sizeof(unsigned char));

            ret_num = clEnqueueUnmapMemObject(acls->device->command_queue,
                    acls->platform->mem_objects[0], clxlatcase, 0, NULL, NULL);
            aclCheckResult(acls, ret_num, "clEnqueueUnmapBuffer(mem_objects[0])");

            result = clEnqueueMapBuffer(acls->device->command_queue,
                    acls->platform->mem_objects[1],
                    CL_TRUE, CL_MAP_WRITE, 0,
                    (2 * MAX_PKT_CACHE_SIZE + 1) * sizeof(int), 0, NULL, NULL, &ret_num);
            aclCheckResult(acls, ret_num, "clEnqueueMapBuffer(mem_objects[1])");

            memset (result, 0, (2 * MAX_PKT_CACHE_SIZE + 1) * sizeof(int));

            ret_num = clEnqueueUnmapMemObject(acls->device->command_queue,
                    acls->platform->mem_objects[1], result, 0, NULL, NULL);
            aclCheckResult(acls, ret_num, "clEnqueueUnmapBuffer(mem_objects[1])");
        }

        ret_num = clSetKernelArg(acls->platform->kernel, 0, sizeof(cl_mem),
                &(acls->platform->mem_objects[0]));
        aclCheckResult(acls, ret_num, "clSetKernelArg(0)");
        
        ret_num = clSetKernelArg(acls->platform->kernel, 1, sizeof(cl_mem),
                &(acls->platform->mem_objects[1]));
        aclCheckResult(acls, ret_num, "clSetKernelArg(1)");
    }
}

static void alvinclFree(){
    if (acls != NULL){
        aclCleanUp(acls);
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
        next = spfac->spfacStateTable[state * SPFAC_ALPHABET_SIZE + *pattern];
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
        spfac->spfacStateTable[state * SPFAC_ALPHABET_SIZE + *pattern] 
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
    for (i = 0; i < spfac->spfacNumStates + 1; i++)
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

    int *tmp_ST;
    SPFAC_PATTERN **tmp_ML; 

    int *ptr_map;

    cl_int ret_num;

    /* Init a Queue */
    queue_init (queue);



    /* Count number of states */
    spfac->spfacMaxStates = 1;
    for (plist = spfac->spfacPatterns; plist != NULL; plist = plist->next)
    {
        spfac->spfacMaxStates += plist->n;
    }
    //spfac->spfacStateTable = (unsigned int*) spfacMalloc (sizeof (unsigned int) * SPFAC_ALPHABET_SIZE * spfac->spfacMaxStates);
    ret_num = posix_memalign((void**)&(spfac->spfacStateTable), MEM_ALIGNMENT, sizeof (int) * SPFAC_ALPHABET_SIZE * spfac->spfacMaxStates);
    aclCheckPointer(acls, spfac->spfacStateTable, "spfac->spfacStateTable");
    memset (spfac->spfacStateTable, 0,
            sizeof (int) * SPFAC_ALPHABET_SIZE * spfac->spfacMaxStates);
    spfac->MatchList =
        (SPFAC_PATTERN**) spfacMalloc (sizeof(SPFAC_PATTERN*) * spfac->spfacMaxStates);

    /* Initialize state zero as a branch */
    spfac->spfacNumStates = 0;

    /* Initialize all States NextStates to FAILED */
    for (k = 0; k < spfac->spfacMaxStates; k++)
    {
        for (i = 0; i < SPFAC_ALPHABET_SIZE; i++)
        {
            spfac->spfacStateTable[k * SPFAC_ALPHABET_SIZE + i] = SPFAC_FAIL_STATE;
        }
    }

    /* Add each Pattern to the State Table */
    for (plist = spfac->spfacPatterns; plist != NULL; plist = plist->next)
    {
        AddPatternStates (spfac, plist);
    }

    /* Sort State */
    ret_num = posix_memalign((void**)&(tmp_ST), MEM_ALIGNMENT, sizeof (int) * SPFAC_ALPHABET_SIZE * (spfac->spfacNumStates + 1));
    aclCheckPointer(acls, tmp_ST, "tmp_ST");
    memset (tmp_ST, 0, sizeof (int) * SPFAC_ALPHABET_SIZE * (spfac->spfacNumStates + 1));
    tmp_ML = (SPFAC_PATTERN**) spfacMalloc (sizeof(SPFAC_PATTERN*) * (spfac->spfacNumStates + 1));
    
    memcpy(&(tmp_ST[0 * SPFAC_ALPHABET_SIZE]), &(spfac->spfacStateTable[0 * SPFAC_ALPHABET_SIZE]), sizeof (int) * SPFAC_ALPHABET_SIZE);
    tmp_ML[0] = spfac->MatchList[0];
    r = 1;
    for (k = 0; k < spfac->spfacNumStates + 1; k++){
        for (i = 0; i < SPFAC_ALPHABET_SIZE; i++){
            if((s = tmp_ST[k * SPFAC_ALPHABET_SIZE + i]) > 0){
                memcpy(&(tmp_ST[r * SPFAC_ALPHABET_SIZE]), &(spfac->spfacStateTable[s * SPFAC_ALPHABET_SIZE]), sizeof (int) * SPFAC_ALPHABET_SIZE);
                tmp_ML[r] = spfac->MatchList[s];
                tmp_ST[k * SPFAC_ALPHABET_SIZE + i] = r;
                r++;
            }
        }
    }
    spfacUnMalloc((void*)(spfac->spfacStateTable));
    spfacUnMalloc((void*)(spfac->MatchList));
    spfac->spfacStateTable = tmp_ST;
    spfac->MatchList = tmp_ML;
    

    /* Add each state's MatchList to all state of it's child stateTable */
    for (k = spfac->spfacNumStates; k > 0; k--){
        if(spfac->MatchList[k] != NULL){
            queue_add(queue, k);
            plist = spfac->MatchList[k];
            while(plist->next != NULL)
                plist = plist->next;
            while(queue_count (queue) > 0){
                r = queue_remove (queue);
                for(i = 0; i < SPFAC_ALPHABET_SIZE; i++){
                    if((s = spfac->spfacStateTable[r * SPFAC_ALPHABET_SIZE + i]) != 0){
                        queue_add (queue, s);
                        px = CopyMatchListEntry (plist);
                        px->next = spfac->MatchList[s];
                        spfac->MatchList[s] = px;
                    }
                }
            }
        }
    }

    /* Mark matched and end node */
    for (k = 0; k < spfac->spfacNumStates + 1; k++){
        if (spfac->MatchList[k] != NULL){
            for (i = 0; i < SPFAC_ALPHABET_SIZE; i++){
                if (spfac->spfacStateTable[k * SPFAC_ALPHABET_SIZE + i] == 0)
                    spfac->spfacStateTable[k * SPFAC_ALPHABET_SIZE + i] = -1;
            }
        }
    }


    /* */
    if (build_tree && neg_list_func)
    {
        spfacBuildMatchStateTrees(spfac, build_tree, neg_list_func);
    }
    //
    if (strcmp(acls->platform->name, "AMD Accelerated Parallel Processing") == 0){
        //printf("AMD\n");

        spfac->mem_object = clCreateBuffer(acls->platform->context,
                CL_MEM_READ_ONLY | CL_MEM_USE_PERSISTENT_MEM_AMD,
                sizeof (int) * SPFAC_ALPHABET_SIZE * (spfac->spfacNumStates + 1), NULL, &ret_num);
        aclCheckResult(acls, ret_num, "clCreateBuffer(spfac->mem_object)");

        ptr_map = clEnqueueMapBuffer(acls->device->command_queue, spfac->mem_object,
                CL_TRUE, CL_MAP_WRITE_INVALIDATE_REGION, 0, 
                sizeof (int) * SPFAC_ALPHABET_SIZE * (spfac->spfacNumStates + 1),
                0, NULL, NULL, &ret_num);
        aclCheckResult(acls, ret_num, "clEnqueueMapBuffer(spfac->mem_object)");
    } else {
        spfac->mem_object = clCreateBuffer(acls->platform->context,
                CL_MEM_READ_ONLY | CL_MEM_ALLOC_HOST_PTR,
                sizeof (int) * SPFAC_ALPHABET_SIZE * (spfac->spfacNumStates + 1), NULL, &ret_num);
        aclCheckResult(acls, ret_num, "clCreateBuffer(spfac->mem_object)");

        ptr_map = clEnqueueMapBuffer(acls->device->command_queue, spfac->mem_object,
                CL_TRUE, CL_MAP_WRITE, 0,
                sizeof (int) * SPFAC_ALPHABET_SIZE * (spfac->spfacNumStates + 1),
                0, NULL, NULL, &ret_num);
        aclCheckResult(acls, ret_num, "clEnqueueMapBuffer(spfac->mem_object)");
    }
    memcpy(ptr_map, spfac->spfacStateTable, sizeof (int) * SPFAC_ALPHABET_SIZE * (spfac->spfacNumStates + 1));

    ret_num = clEnqueueUnmapMemObject(acls->device->command_queue, spfac->mem_object, ptr_map, 0, NULL, NULL);
    aclCheckResult(acls, ret_num, "clEnqueueUnmapBuffer(spfac->mem_object)");

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
    int nfound = 0, nr;
    SPFAC_PATTERN ** MatchList = spfac->MatchList;
    int n_cl = (n % 64) ? (n / 64 + 1) * 64 : n;
    n_cl /= 32;
    int * result;
    int * presult;
    int index;
    cl_mem mem_object;
    size_t global_work_group_size[1] = { n_cl };
    size_t local_work_group_size[1] = { 64 };

    cl_int ret_num;
    //
    
    mem_object = clCreateBuffer(acls->platform->context,
            CL_MEM_READ_ONLY | CL_MEM_USE_HOST_PTR, sizeof(unsigned char) * n, Tx, &ret_num);
    aclCheckResult(acls, ret_num, "clCreateBuffer(T)");

    ret_num = clSetKernelArg(acls->platform->kernel, 2, sizeof(cl_mem), &(mem_object));
    aclCheckResult(acls, ret_num, "clSetKernelArg(2)");

    //T = clEnqueueMapBuffer(acls->device->command_queue, acls->platform->mem_objects[1], CL_TRUE, CL_MAP_WRITE_INVALIDATE_REGION, 0, n_cl * sizeof(unsigned char), 0, NULL, NULL, &ret_num);
    //aclCheckResult(acls, ret_num, "clEnqueueMapBuffer(mem_objects[1])");

    //memcpy(T, Tx, n * sizeof(unsigned char));
    //memset((T + n * sizeof(unsigned char)), 0, n_cl - n);

    //ret_num = clEnqueueUnmapMemObject(acls->device->command_queue, acls->platform->mem_objects[1], T, 0, NULL, NULL);
    //aclCheckResult(acls, ret_num, "clEnqueueUnmapBuffer(mem_objects[1])");

    //
    ret_num = clSetKernelArg(acls->platform->kernel, 3, sizeof(cl_mem), &(spfac->mem_object));
    aclCheckResult(acls, ret_num, "clSetKernelArg(3)");
    //ret_num = clSetKernelArg(acls->platform->kernel, 4, sizeof(int), &(n));
    //aclCheckResult(acls, ret_num, "clSetKernelArg(4)");



    //

    ret_num = clEnqueueNDRangeKernel(acls->device->command_queue, acls->platform->kernel,
            1, NULL, global_work_group_size, local_work_group_size, 0, NULL, NULL);
    aclCheckResult(acls, ret_num, "clEnqueueNDRangeKernel");
    

    //
    result = clEnqueueMapBuffer(acls->device->command_queue, acls->platform->mem_objects[1],
            CL_TRUE, CL_MAP_WRITE, 0, (11) * sizeof(int), 0, NULL, NULL, &ret_num);
    aclCheckResult(acls, ret_num, "clEnqueueMapBuffer(mem_objects[1]).2");
    //
    
    //printf("m:%d\n", *result);
    nr = *result;
    if (nr > 5){
        *result = 0;
        ret_num = clEnqueueUnmapMemObject(acls->device->command_queue,
                acls->platform->mem_objects[1], result, 0, NULL, NULL);
        aclCheckResult(acls, ret_num, "clEnqueueUnmapBuffer(mem_objects[1])");

        result = clEnqueueMapBuffer(acls->device->command_queue, acls->platform->mem_objects[1],
                CL_TRUE, CL_MAP_READ, 0, (nr * 2 + 1) * sizeof(int), 0, NULL, NULL, &ret_num);
        aclCheckResult(acls, ret_num, "clEnqueueMapBuffer(mem_objects[1].3)");
    }
    

    presult = result + 1;
    while (nr != 0){
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
        nr--;
    }
    //
    ret_num = clEnqueueUnmapMemObject(acls->device->command_queue, acls->platform->mem_objects[1],
            result, 0, NULL, NULL);
    aclCheckResult(acls, ret_num, "clEnqueueUnmapBuffer(mem_objects[1])");
    
    //clFinish(acls->device->command_queue);
    //aclCheckResult(acls, ret_num, "clFinish");

    clReleaseMemObject(mem_object);

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
    for (i = 0; i < spfac->spfacNumStates + 1; i++)
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

    for (k = 0; k < spfac->spfacNumStates + 1; k++){
        printf("%d\t", k);
        for (i = 0; i < SPFAC_ALPHABET_SIZE; i++)
        {
            next = spfac->spfacStateTable[k * SPFAC_ALPHABET_SIZE + i];

            if( next > SPFAC_FAIL_STATE )
            {
                if( isprint(i) )
                    printf("%3c->%-5d\t",i,next);
                else{
                    printf("%3d->%-5d\t",i,next);
                }
            }
        }
        if (spfac->MatchList[k] != NULL){
            mlist = spfac->MatchList[k];
            mc = 0;
            while(mlist != NULL){
                mc++;
                mlist = mlist->next;
            }
            printf("Match:%d\t", mc);

        }
        printf("\n");
    }
    printf("Num of states:%d\n", spfac->spfacNumStates);
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

#define SPFAC_MAIN
#ifdef SPFAC_MAIN

/*
 *    A Match is found
 */
    int
MatchFound (void * id, void *tree, int index, void *data, void *neg_list)
{
    fprintf (stdout, "%s\n", (char *) id);
    return 0;
}

MatchFound2 (void * id, void *tree, int index, void *data, void *neg_list)
{
    //fprintf (stdout, "%s\n", (char *) id);
    return 0;
}

void usage()
{
    printf("Usage: --help\n");
    printf("   or: --version\n");
    printf("   or: --mode=test text pattern [pattern...]\n");
    printf("   or: --mode=profiling\n");
    printf("       [--device=cpu|gpu] [--kernel=NUM] [--random]\n");
    printf("       [--cache-size=SIZE] [--num-cache=NUM] [--patterns=NUM]\n");
}
/*
 *
 */
int main(int argc, char **argv){
    SPFAC_STRUCT * spfac;

    char *charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz,./;\"'<>?";
    char *text;
    char *pattern_s = "CCCC";
    char *pattern_r;
    
    int nocase = 1;
    int current_state = 0;
    
    unsigned char mode = 0;
    int rand_c = 0;
    int cache_size = 10485760; 
    int num_cache = 1;
    int num_pattern =  1;

    cl_ulong start, end, use;
    double band_width;

    int ret;
    int i, j;
    int pattern_len;

    
    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            {"help",         no_argument,        NULL,  'h' },
            {"version",      no_argument,        NULL,  'v' },
            {"mode",         required_argument,  NULL,  'm' },
            {"device",       required_argument,  NULL,  'd' },
            {"kernel",       required_argument,  NULL,  'k' },
            {"random",       no_argument,        NULL,  'r' },
            {"cache-size",   required_argument,  NULL,  'c' },
            {"num-cache",    required_argument,  NULL,  'n' },
            {"patterns",     required_argument,  NULL,  'p' },
            {0,              0,                  NULL,  0 }
        };

        ret = getopt_long(argc, argv, "vhm:d:k:rc:n:p:",
                long_options, &option_index);
        if (ret == -1)
            break;

        switch (ret) {
            case 'm':
                mode = optarg[0];
                if ((mode != 'p') && (mode != 't')){
                    exit(EXIT_FAILURE);
                }
                break;
            case 'd':
                if (optarg[0] == 'c'){
                    DEVICE_TYPE = CL_DEVICE_TYPE_CPU;
                } else if (optarg[0] == 'g'){
                    DEVICE_TYPE = CL_DEVICE_TYPE_GPU;
                } else {
                    exit(EXIT_FAILURE);
                }
                break;
            case 'k':
                KERNEL_ID = atoi(optarg);
                break;
            case 'r':
                rand_c = 1;
                break;
            case 'c':
                cache_size = atoi(optarg);
                break;
            case 'n':
                num_cache = atoi(optarg);
                break;
            case 'p':
                num_pattern = atoi(optarg);
                break;
            case 'v':
                printf("Secure Parallel Failureless-AC Alogithm 1.0\n");
                exit(EXIT_SUCCESS);
                break;
            case 'h':
                usage();
                exit(EXIT_SUCCESS);
                break;
            case 0:
                fprintf(stderr, "ERROR: unknow arg!\n");
                exit(EXIT_FAILURE);
                break;
            case '?':
                //fprintf(stderr, "ERROR: unknow arg!\n");
                //exit(EXIT_FAILURE);
                break;
            default:
                fprintf(stderr, "ERROR: unknow arg!\n");
                exit(EXIT_FAILURE);
        }
    }

    if ((mode == 't') && (argc - optind >= 2)){
        spfac = spfacNew (NULL, NULL, NULL);
        ret = posix_memalign((void**)&(text), MEM_ALIGNMENT, sizeof (char) * 2048);
        aclCheckPointer(acls, text, "text");
        memset (text, 0, sizeof (char) * 2048);
        strcpy (text, argv[optind]);
        optind++;

        while (optind < argc){
            spfacAddPattern (spfac, argv[optind], strlen(argv[optind]), nocase, 0, 0, 0,
                (void*)argv[optind], 0);
            optind++;
        }

        spfacCompile (spfac, NULL, NULL);
        Print_DFA(spfac);
        spfacSearch (spfac, text, sizeof (char) * 2048, MatchFound, NULL, &current_state);
        free(text);
        spfacFree (spfac);
        return (0);

    }

    spfac = spfacNew (NULL, NULL, NULL);
    
    ret = posix_memalign((void**)&(text), MEM_ALIGNMENT, sizeof (char) * cache_size);
    aclCheckPointer(acls, text, "text");

    if (rand_c == 1){
        srand(time(0));
        for (i = 0; i < (cache_size -1); i++){
            text[i] =  charset[rand() % strlen(charset)];
        }
        text[cache_size -1] = '\0';
        
        pattern_r = calloc(num_pattern, 21 * sizeof(char));
        for (i = 0; i < num_pattern; i++){
            pattern_len = (int)3 + rand() % 18;
            for (j = 0; j < pattern_len; j++)
                pattern_r[i * 21 + j] = charset[rand() % strlen(charset)];
            pattern_r[i* 21 + pattern_len] = '\0';
            spfacAddPattern(spfac, (pattern_r + i * 21), pattern_len, 
                    nocase, 0, 0, 0, (void*)(pattern_r + i * 21), 0);
        }
    } else {
        memset (text, 'A', sizeof (char) * cache_size);
        spfacAddPattern(spfac, pattern_s, strlen (pattern_s), nocase, 0, 0, 0, (void*)pattern_s, 0);
    }

    spfacCompile (spfac, NULL, NULL);

    start = aclTimeNanos();
    for (i = 0; i < num_cache; i++){
        spfacSearch (spfac, text, cache_size, MatchFound, NULL, &current_state);
    }
    end = aclTimeNanos();
    use = end - start;

    band_width = 8.0 * cache_size * num_cache / use * 1000 / 1024 * 1000 / 1024 * 1000 / 1024;
    printf("Cache size:%8d Byte\tBandwidth:%f Gb/s\n", cache_size, band_width);
    printf("Num cache:%d\nNum_pattern:%d\n", num_cache, num_pattern);

    free(text);
    if (rand_c == 1)
        free(pattern_r);
    spfacFree (spfac);

    return 0;
}
#endif /* SPFAC_MAIN */


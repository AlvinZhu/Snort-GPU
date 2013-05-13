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

#define MEMASSERT(p,s) if(!p){fprintf(stderr,"SPFAC-No Memory: %s!\n",s);exit(0);}

#ifdef DEBUG_SPFAC
static int max_memory = 0;
#endif


/*
*
*/
static void *
AC_MALLOC (int n)
{
  void *p;
  p = calloc (1,n);
#ifdef DEBUG_AC
  if (p)
    max_memory += n;
#endif
  return p;
}


/*
*
*/
static void
AC_FREE (void *p)
{
  if (p)
    free (p);
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
      q = s->tail = s->head = (QNODE *) AC_MALLOC (sizeof (QNODE));
      MEMASSERT (q, "queue_add");
      q->state = state;
      q->next = 0;
    }
  else
    {
      q = (QNODE *) AC_MALLOC (sizeof (QNODE));
      MEMASSERT (q, "queue_add");
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
      AC_FREE (q);
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


/*
*
*/
static SPFAC_PATTERN *
CopyMatchListEntry (SPFAC_PATTERN * px)
{
  SPFAC_PATTERN * p;
  p = (SPFAC_PATTERN *) AC_MALLOC (sizeof (SPFAC_PATTERN));
  MEMASSERT (p, "CopyMatchListEntry");
  memcpy (p, px, sizeof (SPFAC_PATTERN));
  px->udata->ref_count++;
  p->next = 0;
  return p;
}


/*
*  Add a pattern to the list of patterns terminated at this state.
*  Insert at front of list.
*/
static void
AddMatchListEntry (SPFAC_STRUCT * spfac, int state, SPFAC_PATTERN * px)
{
  SPFAC_PATTERN * p;
  p = (SPFAC_PATTERN *) AC_MALLOC (sizeof (SPFAC_PATTERN));
  MEMASSERT (p, "AddMatchListEntry");
  memcpy (p, px, sizeof (SPFAC_PATTERN));
  p->next = spfac->spfacStateTable[state].MatchList;
  spfac->spfacStateTable[state].MatchList = p;
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
      next = spfac->spfacStateTable[state].NextState[*pattern];
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
      spfac->spfacStateTable[state].NextState[*pattern] = spfac->spfacNumStates;
      state = spfac->spfacNumStates;
    }

  AddMatchListEntry (spfac, state, p);
}


/*
*   Build Non-Deterministic Finite Automata
*/
static void
Build_NFA (SPFAC_STRUCT * spfac)
{
  int r, s;
  int i;
  QUEUE q, *queue = &q;
  SPFAC_PATTERN * mlist=0;
  SPFAC_PATTERN * px=0;

    /* Init a Queue */
    queue_init (queue);

    /* Add the state 0 transitions 1st */
    for (i = 0; i < SPFAC_ALPHABET_SIZE; i++)
    {
      s = spfac->spfacStateTable[0].NextState[i];
      if (s)
      {
        queue_add (queue, s);
        spfac->spfacStateTable[s].FailState = 0;
      }
    }

    /* Build the fail state transitions for each valid state */
    while (queue_count (queue) > 0)
    {
      r = queue_remove (queue);

      /* Find Final States for any Failure */
      for (i = 0; i < SPFAC_ALPHABET_SIZE; i++)
      {
        int fs, next;
        if ((s = spfac->spfacStateTable[r].NextState[i]) != SPFAC_FAIL_STATE)
        {
          queue_add (queue, s);
          fs = spfac->spfacStateTable[r].FailState;

          /*
           *  Locate the next valid state for 'i' starting at s
           */
          while ((next=spfac->spfacStateTable[fs].NextState[i]) ==
                 SPFAC_FAIL_STATE)
          {
            fs = spfac->spfacStateTable[fs].FailState;
          }

          /*
           *  Update 's' state failure state to point to the next valid state
           */
          spfac->spfacStateTable[s].FailState = next;

          /*
           *  Copy 'next'states MatchList to 's' states MatchList,
           *  we copy them so each list can be AC_FREE'd later,
           *  else we could just manipulate pointers to fake the copy.
           */
          for (mlist  = spfac->spfacStateTable[next].MatchList;
               mlist != NULL ;
               mlist  = mlist->next)
          {
              px = CopyMatchListEntry (mlist);

              if( !px )
              {
                FatalError("*** Out of memory Initializing Aho Corasick in spfacx.c ****");
              }

              /* Insert at front of MatchList */
              px->next = spfac->spfacStateTable[s].MatchList;
              spfac->spfacStateTable[s].MatchList = px;
          }
        }
      }
    }

    /* Clean up the queue */
    queue_free (queue);
}


/*
*   Build Deterministic Finite Automata from NFA
*/
static void
Convert_NFA_To_DFA (SPFAC_STRUCT * spfac)
{
  int r, s;
  int i;
  QUEUE q, *queue = &q;

    /* Init a Queue */
    queue_init (queue);

    /* Add the state 0 transitions 1st */
    for (i = 0; i < SPFAC_ALPHABET_SIZE; i++)
    {
      s = spfac->spfacStateTable[0].NextState[i];
      if (s)
      {
        queue_add (queue, s);
      }
    }

    /* Start building the next layer of transitions */
    while (queue_count (queue) > 0)
    {
      r = queue_remove (queue);

      /* State is a branch state */
      for (i = 0; i < SPFAC_ALPHABET_SIZE; i++)
      {
        if ((s = spfac->spfacStateTable[r].NextState[i]) != SPFAC_FAIL_STATE)
        {
            queue_add (queue, s);
        }
        else
        {
            spfac->spfacStateTable[r].NextState[i] =
            spfac->spfacStateTable[spfac->spfacStateTable[r].FailState].
            NextState[i];
        }
      }
    }

    /* Clean up the queue */
    queue_free (queue);
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
  p = (SPFAC_STRUCT *) AC_MALLOC (sizeof (SPFAC_STRUCT));
  MEMASSERT (p, "spfacNew");
  if (p)
  {
    memset (p, 0, sizeof (SPFAC_STRUCT));
    p->userfree              = userfree;
    p->optiontreefree        = optiontreefree;
    p->neg_list_free         = neg_list_free;
  }
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
  plist = (SPFAC_PATTERN *) AC_MALLOC (sizeof (SPFAC_PATTERN));
  MEMASSERT (plist, "spfacAddPattern");
  plist->patrn = (unsigned char *) AC_MALLOC (n);
  ConvertCaseEx (plist->patrn, pat, n);
  plist->casepatrn = (unsigned char *) AC_MALLOC (n);
  memcpy (plist->casepatrn, pat, n);

  plist->udata = (SPFAC_USERDATA *)AC_MALLOC(sizeof(SPFAC_USERDATA));
  MEMASSERT (plist->udata, "spfacAddPattern");
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
        for ( mlist=spfac->spfacStateTable[i].MatchList;
              mlist!=NULL;
              mlist=mlist->next )
        {
            if (mlist->udata->id)
            {
                if (mlist->negative)
                {
                    neg_list_func(mlist->udata->id, &spfac->spfacStateTable[i].MatchList->neg_list);
                }
                else
                {
                    build_tree(mlist->udata->id, &spfac->spfacStateTable[i].MatchList->rule_option_tree);
                }
            }

            cnt++;
        }

        if (spfac->spfacStateTable[i].MatchList)
        {
            /* Last call to finalize the tree */
            build_tree(NULL, &spfac->spfacStateTable[i].MatchList->rule_option_tree);
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
    SPFAC_PATTERN * plist;

    /* Count number of states */
    spfac->spfacMaxStates = 1;
    for (plist = spfac->spfacPatterns; plist != NULL; plist = plist->next)
    {
        spfac->spfacMaxStates += plist->n;
    }
    spfac->spfacStateTable =
        (SPFAC_STATETABLE *) AC_MALLOC (sizeof (SPFAC_STATETABLE) *
                                        spfac->spfacMaxStates);
    MEMASSERT (spfac->spfacStateTable, "spfacCompile");
    memset (spfac->spfacStateTable, 0,
        sizeof (SPFAC_STATETABLE) * spfac->spfacMaxStates);

    /* Initialize state zero as a branch */
    spfac->spfacNumStates = 0;

    /* Initialize all States NextStates to FAILED */
    for (k = 0; k < spfac->spfacMaxStates; k++)
    {
        for (i = 0; i < SPFAC_ALPHABET_SIZE; i++)
        {
            spfac->spfacStateTable[k].NextState[i] = SPFAC_FAIL_STATE;
        }
    }

    /* Add each Pattern to the State Table */
    for (plist = spfac->spfacPatterns; plist != NULL; plist = plist->next)
    {
        AddPatternStates (spfac, plist);
    }

    /* Set all failed state transitions to return to the 0'th state */
    for (i = 0; i < SPFAC_ALPHABET_SIZE; i++)
    {
        if (spfac->spfacStateTable[0].NextState[i] == SPFAC_FAIL_STATE)
        {
            spfac->spfacStateTable[0].NextState[i] = 0;
        }
    }

    /* Build the NFA  */
    Build_NFA (spfac);

    /* Convert the NFA to a DFA */
    Convert_NFA_To_DFA (spfac);

    /*
      printf ("SPFAC-Max Memory: %d bytes, %d states\n", max_memory,
        spfac->spfacMaxStates);
     */

    //Print_DFA( spfac );

    if (build_tree && neg_list_func)
    {
        spfacBuildMatchStateTrees(spfac, build_tree, neg_list_func);
    }

    return 0;
}


static unsigned char Tc[64*1024];

/*
*   Search Text or Binary Data for Pattern matches
*/
int
spfacSearch (SPFAC_STRUCT * spfac, unsigned char *Tx, int n,
            int (*Match)(void * id, void *tree, int index, void *data, void *neg_list),
            void *data, int* current_state )
{
    int state = 0;
    SPFAC_PATTERN * mlist;
    unsigned char *Tend;
    SPFAC_STATETABLE * StateTable = spfac->spfacStateTable;
    int nfound = 0;
    unsigned char *T;
    int index;

    /* Case conversion */
    ConvertCaseEx (Tc, Tx, n);
    T = Tc;
    Tend = T + n;

    if ( !current_state )
    {
        return 0;
    }

    state = *current_state;

    for (; T < Tend; T++)
    {
        state = StateTable[state].NextState[*T];

        if( StateTable[state].MatchList != NULL )
        {
            mlist = StateTable[state].MatchList;
            index = T - mlist->n + 1 - Tc;
            nfound++;
            if (Match (mlist->udata->id, mlist->rule_option_tree, index, data, mlist->neg_list) > 0)
            {
                *current_state = state;
                return nfound;
            }
        }
    }
    *current_state = state;
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
        mlist = spfac->spfacStateTable[i].MatchList;
        while (mlist)
        {
            ilist = mlist;
            mlist = mlist->next;

            ilist->udata->ref_count--;
            if (ilist->udata->ref_count == 0)
            {
                if (spfac->userfree && ilist->udata->id)
                    spfac->userfree(ilist->udata->id);

                AC_FREE(ilist->udata);
            }

            if (ilist->rule_option_tree && spfac->optiontreefree)
            {
                spfac->optiontreefree(&(ilist->rule_option_tree));
            }

            if (ilist->neg_list && spfac->neg_list_free)
            {
                spfac->neg_list_free(&(ilist->neg_list));
            }

            AC_FREE (ilist);
        }
    }
    AC_FREE (spfac->spfacStateTable);
    mlist = spfac->spfacPatterns;
    while(mlist)
    {
        ilist = mlist;
        mlist = mlist->next;
        AC_FREE(ilist->patrn);
        AC_FREE(ilist->casepatrn);
        AC_FREE(ilist);
    }
    AC_FREE (spfac);
}

int spfacPatternCount ( SPFAC_STRUCT * spfac )
{
    return spfac->numPatterns;
}

/*
 *
 */
/*
static void Print_DFA( SPFAC_STRUCT * spfac )
{
    int k;
    int i;
    int next;

    for (k = 0; k < spfac->spfacMaxStates; k++)
    {
      for (i = 0; i < SPFAC_ALPHABET_SIZE; i++)
    {
      next = spfac->spfacStateTable[k].NextState[i];

      if( next == 0 || next ==  SPFAC_FAIL_STATE )
      {
           if( isprint(i) )
             printf("%3c->%-5d\t",i,next);
           else
             printf("%3d->%-5d\t",i,next);
      }
    }
      printf("\n");
    }

}
*/


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


#ifdef SPFAC_MAIN

/*
*  Text Data Buffer
*/
unsigned char text[512];

/*
*    A Match is found
*/
  int
MatchFound (unsigned id, int index, void *data)
{
  fprintf (stdout, "%s\n", (char *) id);
  return 0;
}


/*
*
*/
  int
main (int argc, char **argv)
{
  int i, nocase = 0;
  SPFAC_STRUCT * spfac;
  if (argc < 3)

    {
      fprintf (stderr,
        "Usage: spfacx pattern word-1 word-2 ... word-n  -nocase\n");
      exit (0);
    }
  spfac = spfacNew ();
  strcpy (text, argv[1]);
  for (i = 1; i < argc; i++)
    if (strcmp (argv[i], "-nocase") == 0)
      nocase = 1;
  for (i = 2; i < argc; i++)

    {
      if (argv[i][0] == '-')
    continue;
      spfacAddPattern (spfac, argv[i], strlen (argv[i]), nocase, 0, 0,
            argv[i], i - 2);
    }
  spfacCompile (spfac);
  spfacSearch (spfac, text, strlen (text), MatchFound, (void *) 0);
  spfacFree (spfac);
  printf ("normal pgm end\n");
  return (0);
}
#endif /*  */


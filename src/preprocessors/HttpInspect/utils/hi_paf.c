/* $Id$ */
/****************************************************************************
 *
 * Copyright (C) 2011-2013 Sourcefire, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation.  You may not use, modify or
 * distribute this program under any other version of the GNU General
 * Public License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 ****************************************************************************/

//--------------------------------------------------------------------
// hi stuff
//
// @file    hi_paf.c
// @author  Russ Combs <rcombs@sourcefire.com>

// the goal is to perform the minimal http paf parsing required for
// correctness while maintaining loose coupling with hi proper:

// * distinguish request from response by presence of http version
//   as first token in first header of response
// * identify head request so response is understood to not have body
// * determine length of body from content-length header
// * determine chunking from transfer-endoding header
// * extract chunk lengths for body chunks
// * determine end of chunks from chunk length of zero

// Support for "Expect: 100-continue" is deferred.  this is so far
// intended to be a standalone, "bolt on" addition to hi but expect
// and certain other cases may require simplified parsing here and
// feedback from hi to reset or otherwise adjust state.

// 1XX, 204, or 304 status responses must not have a body per RFC but
// if other headers indicate a body is present we will process that.
// This is different for head responses because content-length or
// transfer-encoding are expected.

// future work:
// * capture headers of interest to hi packet processing (including
//   offset and length) so hi doesn't have to search, size, or unfold
// * fsm initialization could possibly be simpler eg by converting
//   strings into state array
//--------------------------------------------------------------------

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "generators.h"
#include "hi_paf.h"
#include "hi_eo_events.h"
#include "decode.h"
#include "snort.h"
#include "stream_api.h"
#include "snort_debug.h"

#define HI_TRACE     // define for state trace

// config stuff
// FIXTHIS replace hi_cap with flow depths or delete altogether?
static uint32_t hi_cap = 0;

// stats
static uint32_t hi_paf_calls = 0;
static uint32_t hi_paf_bytes = 0;

//--------------------------------------------------------------------
// session data
//--------------------------------------------------------------------

#define HIF_REQ 0x0001  // message is request
#define HIF_RSP 0x0002  // message is response
#define HIF_LEN 0x0004  // content-length
#define HIF_CHK 0x0008  // transfer-encoding: chunked
#define HIF_NOB 0x0010  // head (no body in response)
#define HIF_NOF 0x0020  // no flush (chunked body follows)
#define HIF_V09 0x0040  // simple request version 0.9
#define HIF_V10 0x0080  // server response version 1.0
#define HIF_V11 0x0100  // server response version 1.1
#define HIF_ERR 0x0200  // flag error for deferred abort (at eoh)
#define HIF_PST 0x0400  // post (requires content-length or chunks)
#define HIF_EOL 0x0800  // already saw at least one eol (for v09)

typedef struct {
    uint32_t len;
    uint16_t flags;
    uint8_t msg;
    uint8_t fsm;
} HiState;

//--------------------------------------------------------------------
// fsm stuff
//--------------------------------------------------------------------

typedef enum {
    ACT_NOP, ACT_NOB, ACT_PST,
    ACT_V09, ACT_V10,  ACT_V11,
    ACT_REQ, ACT_RSP,
    ACT_SHI, ACT_SHX, 
    ACT_LNB, ACT_LNC, ACT_LN0,
    ACT_CHK, ACT_CK0
} Action;

typedef struct {
    uint8_t state;
    uint8_t event;
    uint8_t match;
    uint8_t other;
    uint8_t action;
} HiFsm;

#define EOL '\n'  // \r is ignored
#define ANY '\0'  // don't care
#define LWS ' '   // space or tab

// these are just convenient jump points to the start
// of blocks; the states MUST match array index
#define Z0 (0)
#define Z1 (Z0+18)
#define Z2 (Z1+18)
#define Z3 (Z2+17)
#define Z4 (Z3+20)
#define Z5 (Z4+7)
#define Z6 (Z5+2)
#define Z7 (Z6+2)
#define Z8 (Z7+2)
#define Z9 (Z8+2)

#define RSP_START_STATE Z0
#define REQ_START_STATE Z1
#define MSG_CHUNK_STATE Z6

static HiFsm hi_fsm[] =
{
    // http version starts response
    { Z0+ 0, 'H', Z0+ 1, Z8   , ACT_NOP },
    { Z0+ 1, 'T', Z0+ 2, Z9   , ACT_NOP },
    { Z0+ 2, 'T', Z0+ 3, Z9   , ACT_NOP },
    { Z0+ 3, 'P', Z0+ 4, Z9   , ACT_NOP },
    { Z0+ 4, '/', Z0+ 5, Z9   , ACT_NOP },
    { Z0+ 5, '1', Z0+ 6, Z9   , ACT_NOP },
    { Z0+ 6, '.', Z0+ 7, Z9   , ACT_NOP },
    { Z0+ 7, '0', Z0+ 9, Z0+ 8, ACT_V10  },
    { Z0+ 8, '1', Z0+ 9, Z9   , ACT_V11  },
    { Z0+ 9, LWS, Z0+10, Z9   , ACT_NOP },
    { Z0+10, LWS, Z0+10, Z0+11, ACT_NOP },
    { Z0+11, '1', Z0+16, Z0+12, ACT_NOB },
    { Z0+12, '2', Z0+14, Z0+13, ACT_NOP },
    { Z0+13, '3', Z0+14, Z0+16, ACT_NOP },
    { Z0+14, '0', Z0+15, Z0+16, ACT_NOP },
    { Z0+15, '4', Z0+17, Z0+16, ACT_NOB },
    { Z0+16, ANY, Z0+17, Z0+17, ACT_NOP },
    { Z0+17, LWS, Z9+ 0, Z0+16, ACT_RSP },

    // head method signals no body in response
    // post method must have content-length or chunks
    { Z1+ 0, 'H', Z1+ 1, Z1+ 5, ACT_NOP },
    { Z1+ 1, 'E', Z1+ 2, Z1+10, ACT_NOP },
    { Z1+ 2, 'A', Z1+ 3, Z1+10, ACT_NOP },
    { Z1+ 3, 'D', Z1+ 4, Z1+10, ACT_NOP },
    { Z1+ 4, LWS, Z1+12, Z1+10, ACT_NOB },
    { Z1+ 5, 'P', Z1+ 6, Z1+10, ACT_NOP },
    { Z1+ 6, 'O', Z1+ 7, Z1+10, ACT_NOP },
    { Z1+ 7, 'S', Z1+ 8, Z1+10, ACT_NOP },
    { Z1+ 8, 'T', Z1+ 9, Z1+10, ACT_NOP },
    { Z1+ 9, LWS, Z1+12, Z1+10, ACT_PST },
    // now tokens before eol to determine version
    // 2 tokens is a 0.9 SimpleRequest (1 line header)
    // 3 tokens is >= 1.0 (1 or more header lines)
    { Z1+10, LWS, Z1+12, Z1+11, ACT_NOP },
    { Z1+11, ANY, Z1+10, Z1+10, ACT_NOP },
    { Z1+12, LWS, Z1+12, Z1+13, ACT_NOP },
    { Z1+13, EOL, Z9+ 0, Z1+14, ACT_V09 },
    { Z1+14, LWS, Z1+16, Z1+15, ACT_NOP },
    { Z1+15, ANY, Z1+13, Z1+13, ACT_NOP },
    { Z1+16, LWS, Z1+16, Z1+17, ACT_NOP },
    { Z1+17, EOL, Z9+ 0, Z9+ 0, ACT_V09 },

    // content-length can be anywhere after 1st header
    { Z2+ 0, 'C', Z2+ 1, Z3   , ACT_NOP },
    { Z2+ 1, 'O', Z2+ 2, Z9   , ACT_NOP },
    { Z2+ 2, 'N', Z2+ 3, Z9   , ACT_NOP },
    { Z2+ 3, 'T', Z2+ 4, Z9   , ACT_NOP },
    { Z2+ 4, 'E', Z2+ 5, Z9   , ACT_NOP },
    { Z2+ 5, 'N', Z2+ 6, Z9   , ACT_NOP },
    { Z2+ 6, 'T', Z2+ 7, Z9   , ACT_NOP },
    { Z2+ 7, '-', Z2+ 8, Z9   , ACT_NOP },
    { Z2+ 8, 'L', Z2+ 9, Z9   , ACT_NOP },
    { Z2+ 9, 'E', Z2+10, Z9   , ACT_NOP },
    { Z2+10, 'N', Z2+11, Z9   , ACT_NOP },
    { Z2+11, 'G', Z2+12, Z9   , ACT_NOP },
    { Z2+12, 'T', Z2+13, Z9   , ACT_NOP },
    { Z2+13, 'H', Z2+14, Z9   , ACT_NOP },
    { Z2+14, LWS, Z2+14, Z2+15, ACT_NOP },
    { Z2+15, ':', Z2+16, Z9   , ACT_NOP },
    { Z2+16, LWS, Z2+16, Z5   , ACT_LN0 },

    // transfer-encoding can be anywhere after 1st header
    { Z3+ 0, 'T', Z3+ 1, Z9   , ACT_NOP },
    { Z3+ 1, 'R', Z3+ 2, Z9   , ACT_NOP },
    { Z3+ 2, 'A', Z3+ 3, Z9   , ACT_NOP },
    { Z3+ 3, 'N', Z3+ 4, Z9   , ACT_NOP },
    { Z3+ 4, 'S', Z3+ 5, Z9   , ACT_NOP },
    { Z3+ 5, 'F', Z3+ 6, Z9   , ACT_NOP },
    { Z3+ 6, 'E', Z3+ 7, Z9   , ACT_NOP },
    { Z3+ 7, 'R', Z3+ 8, Z9   , ACT_NOP },
    { Z3+ 8, '-', Z3+ 9, Z9   , ACT_NOP },
    { Z3+ 9, 'E', Z3+10, Z9   , ACT_NOP },
    { Z3+10, 'N', Z3+11, Z9   , ACT_NOP },
    { Z3+11, 'C', Z3+12, Z9   , ACT_NOP },
    { Z3+12, 'O', Z3+13, Z9   , ACT_NOP },
    { Z3+13, 'D', Z3+14, Z9   , ACT_NOP },
    { Z3+14, 'I', Z3+15, Z9   , ACT_NOP },
    { Z3+15, 'N', Z3+16, Z9   , ACT_NOP },
    { Z3+16, 'G', Z3+17, Z9   , ACT_NOP },
    { Z3+17, LWS, Z3+17, Z3+18, ACT_NOP },
    { Z3+18, ':', Z3+19, Z9   , ACT_NOP },
    { Z3+19, LWS, Z3+19, Z4   , ACT_NOP },

    // only recognized encoding
    { Z4+ 0, 'C', Z4+ 1, Z9   , ACT_NOP },
    { Z4+ 1, 'H', Z4+ 2, Z9   , ACT_NOP },
    { Z4+ 2, 'U', Z4+ 3, Z9   , ACT_NOP },
    { Z4+ 3, 'N', Z4+ 4, Z9   , ACT_NOP },
    { Z4+ 4, 'K', Z4+ 5, Z9   , ACT_NOP },
    { Z4+ 5, 'E', Z4+ 6, Z9   , ACT_NOP },
    { Z4+ 6, 'D', Z9   , Z9   , ACT_CHK },

    // extract decimal content length
    { Z5+ 0, EOL, Z2   , Z5+ 1, ACT_LNB },
    { Z5+ 1, ANY, Z5   , Z5   , ACT_SHI },

    // extract hex chunk length
    { Z6+ 0, EOL, Z7   , Z6+ 1, ACT_LNC },
    { Z6+ 1, ANY, Z6   , Z6   , ACT_SHX },

    // skip to end of line after chunk data
    { Z7+ 0, EOL, Z6   , Z7+ 1, ACT_LN0 },
    { Z7+ 1, ANY, Z7   , Z7   , ACT_NOP },

    // ignore empty lines before start of message
    { Z8+ 0, LWS, Z0   , Z8+ 1, ACT_NOP },
    { Z8+ 1, EOL, Z0   , Z9+ 1, ACT_NOP },

    // skip to end of line
    { Z9+ 0, EOL, Z2   , Z9+ 1, ACT_NOP },
    { Z9+ 1, ANY, Z9   , Z9   , ACT_NOP }
};

//--------------------------------------------------------------------
// actions
//--------------------------------------------------------------------

static inline int dton (int c)
{
    return c - '0';
}

static inline int xton (int c)
{
    if ( isdigit(c) )
        return c - '0';

    if ( isupper(c) )
        return c - 'A' + 10;

    return c - 'a' + 10;
}

static inline void hi_paf_event_post ()
{
    SnortEventqAdd(
        GENERATOR_SPP_HTTP_INSPECT_CLIENT,
        HI_EO_CLIENT_UNBOUNDED_POST+1, 1, 0, 3,
        HI_EO_CLIENT_UNBOUNDED_POST_STR, NULL);
}

static inline void hi_paf_event_simple ()
{
    SnortEventqAdd(
        GENERATOR_SPP_HTTP_INSPECT_CLIENT,
        HI_EO_CLIENT_SIMPLE_REQUEST+1, 1, 0, 3,
        HI_EO_CLIENT_SIMPLE_REQUEST_STR, NULL);
}

static inline void hi_paf_event_msg_size ()
{
    SnortEventqAdd(
        GENERATOR_SPP_HTTP_INSPECT,
        HI_EO_CLISRV_MSG_SIZE_EXCEPTION+1, 1, 0, 3,
        HI_EO_CLISRV_MSG_SIZE_EXCEPTION_STR, NULL);
}

static inline PAF_Status hi_exec (HiState* s, Action a, int c)
{
    switch ( a )
    {
    case ACT_NOP:
        break;
    case ACT_V09:
        s->flags |= HIF_V09|HIF_ERR;
        break;
    case ACT_V10:
        s->flags |= HIF_V10;
        break;
    case ACT_V11:
        s->flags |= HIF_V11;
        break;
    case ACT_NOB:
        s->flags |= HIF_NOB;
        break;
    case ACT_PST:
        s->flags |= HIF_PST;
        break;
    case ACT_REQ:
        s->flags |= HIF_REQ;
        break;
    case ACT_RSP:
        s->flags |= HIF_RSP;
        break;
    case ACT_SHI:
        if ( s->flags & HIF_ERR )
            break;
        if ( isdigit(c) && (s->len < 429496728) )
            s->len = (10 * s->len) + dton(c);
        else
        {
            hi_paf_event_msg_size();
            s->flags |= HIF_ERR;
        }
        break;
    case ACT_SHX:
        if ( s->flags & HIF_ERR )
            break;
        if ( isxdigit(c) && !(s->len & 0xF8000000) )
            s->len = (s->len << 4) + xton(c);
        else
        {
            hi_paf_event_msg_size();
            s->flags |= HIF_ERR;
            return PAF_FLUSH;
        }
        break;
    case ACT_LNB:
        s->flags |= HIF_LEN;
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_PAF,
            "%s: lnb=%u\n", __FUNCTION__, s->len);)
        break;
    case ACT_LNC:
        s->flags |= HIF_LEN;
        DEBUG_WRAP(DebugMessage(DEBUG_STREAM_PAF,
            "%s: lnc=%u\n", __FUNCTION__, s->len);)
        if ( s->len )
            return PAF_SKIP;
        s->flags &= ~HIF_NOF;
        s->msg = 3;
        break;
    case ACT_LN0:
        s->len = 0;
        break;
    case ACT_CHK:
        s->flags |= HIF_CHK;
        break;
    case ACT_CK0:
        s->flags |= HIF_NOF;
        s->flags &= ~HIF_CHK;
        s->fsm = MSG_CHUNK_STATE;
        s->len = 0;
        break;
    }
    return PAF_SEARCH;
}

//--------------------------------------------------------------------
// control
//--------------------------------------------------------------------

// this is the 2nd step of stateful scanning, which executes
// the fsm.
static PAF_Status hi_scan_fsm (HiState* s, int c)
{
    HiFsm* m = hi_fsm + s->fsm;
#ifdef HI_TRACE
#ifdef DEBUG_MSGS
    uint8_t prev = s->fsm;
#endif
#endif

    if ( c == '\t' )
        c = LWS;
    else
        c = toupper(c);

    do
    {
        if ( !m->event || (m->event == c) )
        {
            s->fsm = m->match;
            break;
        }
        s->fsm = m->other;
        m = hi_fsm + s->fsm;
    }
    while ( 1 );

#ifdef HI_TRACE
    DEBUG_WRAP(DebugMessage(DEBUG_STREAM_PAF,
        "%d[0x%2X, '%c'] -> %d,%d\n",
        prev, c, isgraph(c) ? c : '.', m->action, s->fsm);)
#endif

    return hi_exec(s, m->action, c);
}

static PAF_Status hi_eoh (HiState* s)
{
    DEBUG_WRAP(DebugMessage(DEBUG_STREAM_PAF,
        "%s: flags=0x%X, len=%u\n", __FUNCTION__, s->flags, s->len);)

    if ( (s->flags & HIF_PST) &&
        !(s->flags & (HIF_CHK|HIF_LEN)) )
    {
        hi_paf_event_post();
        s->flags |= HIF_ERR;
    } 
    if ( (s->flags & HIF_ERR) ||
        ((s->flags & HIF_NOB) && (s->flags & HIF_RSP))
    ) {
        if ( s->flags & HIF_V09 )
            hi_paf_event_simple();

        hi_exec(s, ACT_LN0, 0);
        return PAF_FLUSH;
    }
    if ( s->flags & HIF_CHK )
    {
        hi_exec(s, ACT_CK0, 0);
        return PAF_SEARCH;
    }
    if ( (s->flags & (HIF_REQ|HIF_LEN)) )
        return PAF_FLUSH;

    if ( (s->flags & HIF_V11) && (s->flags & HIF_RSP) )
    {
        hi_exec(s, ACT_LN0, 0);
        hi_paf_event_msg_size();
        return PAF_FLUSH;
    }
    return PAF_ABORT;
}

// http messages are scanned statefully, char-by-char, in
// two steps.  this is the 1st step, which figures out
// end-of-line (eol) and end-of-headers (eoh) from the byte
// stream.  also unfolds headers before fsm scanning.  this
// simplified version ignores \r (in the spirit of send strict,
// recv tolerant, but it would only take 2 more states to check
// for \r).  the 2nd step is hi_scan_fsm().
static inline PAF_Status hi_scan_msg (HiState* s, int c, uint32_t* fp)
{
    PAF_Status paf = PAF_SEARCH;

    if ( c == '\r' )
    {
        *fp = 0;
        return paf;
    }
    switch ( s->msg )
    {
    case 0:
        if ( c == '\n' )
        {
            if ( !(s->flags & HIF_EOL) )
            {
                s->flags |= HIF_EOL;
                paf = hi_scan_fsm(s, EOL);

                if ( s->flags & HIF_V09 )
                    paf = hi_eoh(s);
                else
                    s->msg = 1;
            }
            else if ( s->flags & HIF_NOF )
                paf = hi_scan_fsm(s, EOL);
            else
                s->msg = 1;
        }
        else
            paf = hi_scan_fsm(s, c);
        break;

    case 1:
        if ( c == '\n' )
        {
            hi_scan_fsm(s, EOL);
            paf = hi_eoh(s);
        }
        else if ( c == ' ' || c == '\t' )
        {
            // folding, just continue
            paf = hi_scan_fsm(s, LWS);
        }
        else
        {
            paf = hi_scan_fsm(s, EOL);

            if ( paf == PAF_SEARCH )
                paf = hi_scan_fsm(s, c);
        }
        s->msg = 0;
        break;

    case 3:
        if ( c == '\n' )
            paf = hi_eoh(s);
        else
            s->msg = 4;
        break;

    case 4:
        if ( c == '\n' )
            s->msg = 3;
        break;
    }
    if ( paf != PAF_SEARCH )
    {
        *fp = s->len;
    }
    return paf;
}

//--------------------------------------------------------------------
// utility
//--------------------------------------------------------------------

static void hi_reset (HiState* s, uint32_t flags)
{
    s->len = s->msg = 0;

    if ( flags & PKT_FROM_CLIENT )
    {
        s->fsm = REQ_START_STATE;
        s->flags = HIF_REQ; 
    }
    else
    {
        s->fsm = RSP_START_STATE ;
        s->flags = HIF_RSP ; 
    }

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM_PAF,
        "%s: fsm=%u, flags=0x%X\n", __FUNCTION__, s->fsm, s->flags);)
}

// verify that HiFsm.state corresponds to array index
// HiFsm.state is used solely for this purpose.
static bool hi_check (void)
{
    int i = 0;
    bool ok = true;
    int max = sizeof(hi_fsm) / sizeof(hi_fsm[0]);

    while ( i < max )
    {
        if ( hi_fsm[i].state != i )
        {
            printf("FATAL: hi_fsm[%d].state = %d\n", i, hi_fsm[i].state);
            ok = false;
        }
        i++;
    }
    return ok;
}

// update flag on peer so head response doesn't expect body
static void hi_update_peer (HiState* s, void* ssn)
{
    void** pv;
    const uint8_t head = (HIF_NOB | HIF_REQ);

    if ( (s->flags & head) != head )
        return;

    pv = stream_api->get_paf_user_data(ssn, 0);

    if ( !*pv )
    {
        *pv = calloc(1, sizeof(HiState));

        if ( *pv )
            hi_reset(*pv, 0);
    }
        
    if ( !*pv )
        return;

    s = *pv;
    s->flags |= HIF_NOB;
}

//--------------------------------------------------------------------
// callback for stateful scanning of in-order raw payload
//--------------------------------------------------------------------

static PAF_Status hi_paf (
    void* ssn, void** pv, const uint8_t* data, uint32_t len,
    uint32_t flags, uint32_t* fp)
{
    HiState* hip = *pv;
    PAF_Status paf = PAF_SEARCH;

    uint32_t n = 0;
    *fp = 0;

    if ( !hip )
    {
        // beware - we allocate here but s5 calls free() directly
        // so no pointers allowed
        hip = calloc(1, sizeof(HiState));

        if ( !hip )
            return PAF_ABORT;

        *pv = hip;

        hi_reset(hip, flags);
    }

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM_PAF,
        "%s: len=%u\n", __FUNCTION__, len);)

    if ( hip->flags & HIF_ERR )
        return PAF_ABORT;

    if ( hi_cap && (hi_paf_bytes > hi_cap) )
        return PAF_ABORT;

    while ( n < len )
    {
        // jump ahead to next linefeed when possible
        if ( (hip->msg == 0) && (hip->fsm == Z9) )
        {
            uint8_t* lf = memchr(data+n, '\n', len-n);
            if ( !lf )
            {
                n = len;
                break;
            }
            n += (lf - (data + n));
        }
        paf = hi_scan_msg(hip, data[n++], fp);

        if ( paf != PAF_SEARCH )
        {
            if ( hip->flags & HIF_ERR )
            {
                *fp = len;
                break;
            }
            *fp += n;

            hi_update_peer(hip, ssn);

            if ( paf != PAF_SKIP )
                hi_reset(hip, flags);
            break;
        }
    } 
    DEBUG_WRAP(DebugMessage(DEBUG_STREAM_PAF,
        "%s: paf=%d, rfp=%u\n", __FUNCTION__, paf, *fp);)

    hi_paf_calls++;
    hi_paf_bytes += n;

    return paf;
}

//--------------------------------------------------------------------
// public stuff
//--------------------------------------------------------------------

int hi_paf_register (uint16_t port, bool client, bool server, tSfPolicyId pid, bool auto_on)
{
    if ( !ScPafEnabled() )
        return 0;

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM_PAF,
        "%s: policy %u, port %u\n", __FUNCTION__, pid, port);)

    if ( !stream_api )
        return -1;

    if ( client )
        stream_api->register_paf_cb(pid, port, true, hi_paf, auto_on);

    if ( server )
        stream_api->register_paf_cb(pid, port, false, hi_paf, auto_on);

    return 0;
}

//--------------------------------------------------------------------

bool hi_paf_init (uint32_t cap)
{
    assert( hi_check() );

    DEBUG_WRAP(DebugMessage(DEBUG_STREAM_PAF,
        "%s: cap=%u\n",  __FUNCTION__, cap);)

    hi_cap = cap;

    return true;
}

void hi_paf_term (void)
{
    DEBUG_WRAP(DebugMessage(DEBUG_STREAM_PAF,
        "%s: calls=%u, bytes=%u\n",  __FUNCTION__,
        hi_paf_calls, hi_paf_bytes);)
}

//--------------------------------------------------------------------

bool hi_paf_simple_request (void* ssn)
{
    if ( ssn )
    {
        HiState** s = (HiState **)stream_api->get_paf_user_data(ssn, 1);

        if ( s && *s )
            return ( (*s)->flags & HIF_V09 );
    }
    return false;
}


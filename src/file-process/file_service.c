/*
 **
 **
 **  Copyright (C) 2012-2013 Sourcefire, Inc.
 **
 **  This program is free software; you can redistribute it and/or modify
 **  it under the terms of the GNU General Public License Version 2 as
 **  published by the Free Software Foundation.  You may not use, modify or
 **  distribute this program under any other version of the GNU General
 **  Public License.
 **
 **  This program is distributed in the hope that it will be useful,
 **  but WITHOUT ANY WARRANTY; without even the implied warranty of
 **  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 **  GNU General Public License for more details.
 **
 **  You should have received a copy of the GNU General Public License
 **  along with this program; if not, write to the Free Software
 **  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 **
 **  Author(s):  Hui Cao <hcao@sourcefire.com>
 **
 **  NOTES
 **  5.25.12 - Initial Source Code. Hcao
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include "sf_types.h"
#include "file_service.h"
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include "file_api.h"
#include "file_config.h"

#include "stream_api.h"
#include "mstring.h"
#include "preprocids.h"
#include "detect.h"
#include "plugbase.h"
#include "active.h"
#include "detection_util.h"

static bool file_type_id_enabled = false;
static bool file_signature_enabled = false;

static Get_file_policy_func get_file_policy = NULL;
static File_type_done_func  file_type_done = NULL;
static File_signature_done_func file_signature_done = NULL;

/*Main File Processing functions */
static int file_process(void* ssnptr, uint8_t* file_data, int data_size, FilePosition position, bool upload);

/*File properties*/
static int get_file_name (void* ssnptr, uint8_t **file_name, uint32_t *name_size);
static uint64_t get_file_size(void* ssnptr);
static uint64_t get_file_processed_size(void* ssnptr);
static bool get_file_direction(void* ssnptr);
static uint8_t *get_file_sig_sha256(void* ssnptr);

static void set_file_name(void* ssnptr, uint8_t * file_name, uint32_t name_size);
static void set_file_direction(void* ssnptr, bool upload);

static void enable_file_type(Get_file_policy_func, File_type_done_func );
static void enable_file_signature (Get_file_policy_func ,File_signature_done_func);

static int64_t get_max_file_depth(void);

FileAPI fileAPI;
FileAPI* file_api = NULL;

void FileAPIInit(void)
{
    fileAPI.version = FILE_API_VERSION5;
    fileAPI.file_process = &file_process;
    fileAPI.get_file_name = &get_file_name;
    fileAPI.get_file_size = &get_file_size;
    fileAPI.get_file_processed_size = &get_file_processed_size;
    fileAPI.get_file_direction = &get_file_direction;
    fileAPI.get_sig_sha256 = &get_file_sig_sha256;
    fileAPI.set_file_name = &set_file_name;
    fileAPI.set_file_direction = &set_file_direction;
    fileAPI.enable_file_type = &enable_file_type;
    fileAPI.enable_file_signature = &enable_file_signature;
    fileAPI.get_max_file_depth = &get_max_file_depth;
    file_api = &fileAPI;
}

void FreeFileConfig(void *conf)
{
    free_file_rules(conf);
    free_file_identifiers(conf);
    free(conf);
}

static FileContext*  get_file_context(void* p, FilePosition position, bool upload)
{
    FileContext* context;
    Packet *pkt = (Packet *)p;
    void *ssnptr = pkt->ssnptr;

    /* Attempt to get a previously allocated context. */
    context  = stream_api->get_application_data(ssnptr, PP_FILE);

    if (context && ((position == SNORT_FILE_MIDDLE) || (position == SNORT_FILE_END)))
        return context;
    else if (!context)
    {
        context = file_context_create();
        stream_api->set_application_data(ssnptr, PP_FILE, context, file_context_free);
    }
    else
    {
        /*Push file event when there is another file in the same packet*/
        if (pkt->packet_flags & PKT_FILE_EVENT_SET)
        {
            SnortEventqLog(snort_conf->event_queue, p);
            SnortEventqReset();
            pkt->packet_flags &= ~PKT_FILE_EVENT_SET;
        }
        file_context_reset(context);
    }
    context->file_type_enabled = file_type_id_enabled;
    context->file_signature_enabled = file_signature_enabled;
#ifdef TARGET_BASED
    /*Check file policy to see whether we want to do either file type or file signature
     * Note: this happen only on the start of session*/
    if (get_file_policy)
    {
        int app_id;
        uint32_t policy_flags = 0;
        app_id = stream_api->get_application_protocol_id(ssnptr);
        policy_flags = get_file_policy(ssnptr, (int16_t)app_id, upload);
        if (!(policy_flags & ENABLE_FILE_TYPE_IDENTIFICATION))
            context->file_type_enabled = false;
        if (!(policy_flags & ENABLE_FILE_SIGNATURE_SHA256))
            context->file_signature_enabled = false;
    }
#endif
    return context;
}

#if defined(DEBUG_MSGS) || defined (REG_TEST)
#define MAX_CONTEXT_INFO_LEN 1024
static void printFileContext (FileContext* context)
{
    char buf[MAX_CONTEXT_INFO_LEN + 1];
    int unused;
    char *cur = buf;
    int used = 0;

    if (!context)
    {
        printf("File context is NULL.\n");
        return;
    }
    unused = sizeof(buf) - 1;
    used = snprintf(cur, unused, "File name: ");

    if (used < 0)
    {
        printf("Fail to output file context\n");
        return;
    }
    unused -= used;
    cur += used;

    if ((context->file_name_size > 0) && (unused > (int) context->file_name_size))
    {
        strncpy(cur, (char *)context->file_name, context->file_name_size );
        unused -= context->file_name_size;
        cur += context->file_name_size;
    }

    if (unused > 0)
    {
        used = snprintf(cur, unused, "\nFile type: %s(%d)",
                file_info_from_ID(context->file_config, context->file_type_id), context->file_type_id);
        unused -= used;
        cur += used;
    }

    if (unused > 0)
    {
        used = snprintf(cur, unused, "\nFile size: %u",
                (unsigned int)context->file_size);
        unused -= used;
        cur += used;
    }

    if (unused > 0)
    {
        used = snprintf(cur, unused, "\nProcessed size: %u\n",
                (unsigned int)context->processed_bytes);
        unused -= used;
        cur += used;
    }

    buf[sizeof(buf) - 1] = '\0';
    printf("%s", buf);
}

static void DumpHex(FILE *fp, const uint8_t *data, unsigned len)
{
    char str[18];
    unsigned i;
    unsigned pos;
    char c;

    FileConfig *file_config =  (FileConfig *)(snort_conf->file_config);

    if (file_config->show_data_depth < (int64_t)len)
        len = file_config->show_data_depth;

    fprintf(fp,"Show length: %d \n", len);
    for (i=0, pos=0; i<len; i++, pos++)
    {
        if (pos == 17)
        {
            str[pos] = 0;
            fprintf(fp, "  %s\n", str);
            pos = 0;
        }
        else if (pos == 8)
        {
            str[pos] = ' ';
            pos++;
            fprintf(fp, "%s", " ");
        }
        c = (char)data[i];
        if (isprint(c) && (c == ' ' || !isspace(c)))
            str[pos] = c;
        else
            str[pos] = '.';
        fprintf(fp, "%02X ", data[i]);
    }
    if (pos)
    {
        str[pos] = 0;
        for (; pos < 17; pos++)
        {
            if (pos == 8)
            {
                str[pos] = ' ';
                pos++;
                fprintf(fp, "%s", "    ");
            }
            else
            {
                fprintf(fp, "%s", "   ");
            }
        }
        fprintf(fp, "  %s\n", str);
    }
}
#endif

static inline void updateFileSize(FileContext* context, int data_size, FilePosition position)
{
    context->processed_bytes += data_size;
    if ((position == SNORT_FILE_END) || (position == SNORT_FILE_FULL))
    {
        context->file_size = context->processed_bytes;
        context->processed_bytes = 0;
    }
}

int file_eventq_add(uint32_t gid, uint32_t sid, char *msg, RuleType type)
{
    OptTreeNode *otn;
    RuleTreeNode *rtn;
    int ret;

    otn = GetOTN(gid, sid, 1, 0, 3, msg);
    if (otn == NULL)
        return 0;

    rtn = getRtnFromOtn(otn, getRuntimePolicy());
    if (rtn == NULL)
    {
        return 0;
    }

    rtn->type = type;

    ret = SnortEventqAdd(gid, sid, 1, 0, 3, msg, otn);
    return(ret);
}

/*
 * Check HTTP partial content header
 * Return: 1: partial content header
 *         0: not http partial content header
 */
static inline int check_http_partial_content(Packet *p)
{

    /*Not HTTP response, return*/
    if ((p->uri_count < HTTP_BUFFER_STAT_CODE + 1) ||
            ((!UriBufs[HTTP_BUFFER_STAT_CODE].uri) || (!UriBufs[HTTP_BUFFER_STAT_CODE].length)))
        return 0;

    /*Not partial content, return*/
    if ((UriBufs[HTTP_BUFFER_STAT_CODE].length != 3) ||
            strncmp((const char *)UriBufs[HTTP_BUFFER_STAT_CODE].uri, "206",
            UriBufs[HTTP_BUFFER_STAT_CODE].length))
        return 0;

    return 1;
}

static int file_process( void* p, uint8_t* file_data, int data_size, FilePosition position, bool upload)
{
    FileContext* context;
    Packet *pkt = (Packet *)p;
    void *ssnptr = pkt->ssnptr;
    /* if both disabled, return immediately*/
    if ((!file_type_id_enabled) && (!file_signature_enabled))
        return 0;
    if (position == SNORT_FILE_POSITION_UNKNOWN)
        return 0;
#if defined(DEBUG_MSGS) && !defined (REG_TEST)
    if (DEBUG_FILE & GetDebugLevel())
#endif
#if defined(DEBUG_MSGS) || defined (REG_TEST)
    DumpHex(stdout, file_data, data_size);
    DEBUG_WRAP(DebugMessage(DEBUG_FILE, "stream pointer %p\n", ssnptr ););
#endif

    context = get_file_context(p, position, upload);

    if(check_http_partial_content(p))
    {
        context->file_type_enabled = false;
        context->file_signature_enabled = false;
        return 0;
    }

    if ((!context->file_type_enabled) && (!context->file_signature_enabled))
        return 0;

    context->file_config = snort_conf->file_config;
    file_direction_set(context,upload);
    /*file type id*/
    if (context->file_type_enabled)
    {
        File_Verdict verdict = FILE_VERDICT_UNKNOWN;

        file_type_id(context, file_data, data_size, position);

        /*Don't care unknown file type*/
        if (context->file_type_id == SNORT_FILE_TYPE_UNKNOWN)
        {
            context->file_type_enabled = false;
            context->file_signature_enabled = false;
            updateFileSize(context,data_size,position);
            return 0;
        }

        if (context->file_type_id != SNORT_FILE_TYPE_CONTINUE)
        {
            if (file_type_done)
                verdict = file_type_done(ssnptr, context->file_type_id, upload);
            context->file_type_enabled = false;
        }

        if (verdict == FILE_VERDICT_LOG )
        {
            file_eventq_add(GENERATOR_FILE_TYPE, context->file_type_id,
                    file_info_from_ID(context->file_config,context->file_type_id), RULE_TYPE__ALERT);
            context->file_signature_enabled = false;
            pkt->packet_flags |= PKT_FILE_EVENT_SET;
        }
        else if (verdict == FILE_VERDICT_BLOCK)
        {
            file_eventq_add(GENERATOR_FILE_TYPE, context->file_type_id,
                    file_info_from_ID(context->file_config,context->file_type_id), RULE_TYPE__DROP);
            DisableAllDetect(p);
            SetPreprocBit(p, PP_PERFMONITOR);
            updateFileSize(context,data_size,position);
            context->file_signature_enabled = false;
            pkt->packet_flags |= PKT_FILE_EVENT_SET;
            return 1;
        }
        else if (verdict == FILE_VERDICT_STOP)
        {
            context->file_signature_enabled = false;

        }
    }
    /*file signature calculation*/
    if (context->file_signature_enabled)
    {
        File_Verdict verdict = FILE_VERDICT_UNKNOWN;

        file_signature_sha256(context, file_data, data_size, position);

#if defined(DEBUG_MSGS) || defined (REG_TEST)
        if (
#if defined(DEBUG_MSGS) && !defined (REG_TEST)
            (DEBUG_FILE & GetDebugLevel()) &&
#endif
            (context->sha256) )
        {
            file_sha256_print(context->sha256);
        }
#endif
        if ((file_signature_done) && context->sha256 )
        {
            verdict = file_signature_done(ssnptr, context->sha256, upload);
        }

        if (verdict == FILE_VERDICT_LOG )
        {
            file_eventq_add(GENERATOR_FILE_SIGNATURE, FILE_SIGNATURE_SHA256,
                    FILE_SIGNATURE_SHA256_STR, RULE_TYPE__ALERT);
            pkt->packet_flags |= PKT_FILE_EVENT_SET;
        }
        else if (verdict == FILE_VERDICT_BLOCK)
        {
            file_eventq_add(GENERATOR_FILE_SIGNATURE, FILE_SIGNATURE_SHA256,
                    FILE_SIGNATURE_SHA256_STR, RULE_TYPE__DROP);
            DisableAllDetect(p);
            SetPreprocBit(p, PP_PERFMONITOR);
            pkt->packet_flags |= PKT_FILE_EVENT_SET;
        }

    }
    updateFileSize(context,data_size,position);
    return 1;
}

static void set_file_name (void* ssnptr, uint8_t* file_name, uint32_t name_size)
{
    /* Attempt to get a previously allocated context. */
    FileContext* context  = stream_api->get_application_data(ssnptr, PP_FILE);

    file_name_set(context, file_name, name_size);
#if defined(DEBUG_MSGS) || defined (REG_TEST)
#if defined(DEBUG_MSGS) && !defined (REG_TEST)
    if (DEBUG_FILE & GetDebugLevel())
#endif
    printFileContext(context);
#endif
}

/* Return 1: file name available,
 *        0: file name is unavailable
 */
static int get_file_name (void* ssnptr, uint8_t **file_name, uint32_t *name_size)
{
    /* Attempt to get a previously allocated context. */
    FileContext* context  = stream_api->get_application_data(ssnptr, PP_FILE);
    return file_name_get(context, file_name, name_size);

}
static uint64_t  get_file_size(void* ssnptr)
{
    /* Attempt to get a previously allocated context. */
    FileContext* context  = stream_api->get_application_data(ssnptr, PP_FILE);

    return file_size_get(context);

}

static uint64_t  get_file_processed_size(void* ssnptr)
{
    /* Attempt to get a previously allocated context. */
    FileContext* context  = stream_api->get_application_data(ssnptr, PP_FILE);

    if (context)
        return (context->processed_bytes);
    else
        return 0;
}

static void set_file_direction(void* ssnptr, bool upload)
{
    /* Attempt to get a previously allocated context. */
    FileContext* context  = stream_api->get_application_data(ssnptr, PP_FILE);

    file_direction_set(context,upload);

}

static bool get_file_direction(void* ssnptr)
{
    /* Attempt to get a previously allocated context. */
    FileContext* context  = stream_api->get_application_data(ssnptr, PP_FILE);

    return file_direction_get(context);

}
static uint8_t *get_file_sig_sha256(void* ssnptr)
{
    /* Attempt to get a previously allocated context. */
    FileContext* context  = stream_api->get_application_data(ssnptr, PP_FILE);

    return file_sig_sha256_get(context);
}

static void enable_file_type(Get_file_policy_func policy_func, File_type_done_func callback)
{
    get_file_policy = policy_func;
    file_type_done = callback;
    file_type_id_enabled = true;
}
static void enable_file_signature(Get_file_policy_func policy_func, File_signature_done_func callback)
{
    get_file_policy = policy_func;
    file_signature_done = callback;
    file_signature_enabled = true;
}

/* Get maximal file depth based on configuration
 * This function must be called after all file services are configured/enabled.
 */
static int64_t get_max_file_depth(void)
{
    int64_t file_depth = -1;

    FileConfig *file_config =  (FileConfig *)(snort_conf->file_config);

    if (!file_config)
        return -1;

    if (file_type_id_enabled)
    {
        /*Unlimited file depth*/
        if (!file_config->file_type_depth)
            return 0;
        file_depth = file_config->file_type_depth;
    }

    if (file_signature_enabled )
    {
        /*Unlimited file depth*/
        if (!file_config->file_signature_depth)
            return 0;

        if (file_config->file_signature_depth > file_depth)
            file_depth = file_config->file_signature_depth;

    }

    return file_depth;
}


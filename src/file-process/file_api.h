/*
 * ** Copyright (C) 2012-2013 Sourcefire, Inc.
 * ** AUTHOR: Hui Cao
 * **
 * ** This program is free software; you can redistribute it and/or modify
 * ** it under the terms of the GNU General Public License Version 2 as
 * ** published by the Free Software Foundation.  You may not use, modify or
 * ** distribute this program under any other version of the GNU General
 * ** Public License.
 * **
 * ** This program is distributed in the hope that it will be useful,
 * ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 * ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * ** GNU General Public License for more details.
 * **
 * ** You should have received a copy of the GNU General Public License
 * ** along with this program; if not, write to the Free Software
 * ** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 * */

/* file_api.h
 *
 * Purpose: Definition of the FileAPI.  To be used as a common interface
 *          for file process access for other preprocessors and detection plugins.
 *
 *  Author(s):  Hui Cao <hcao@sourcefire.com>
 *
 *  NOTES
 *  5.25.12 - Initial Source Code. Hcao
 */

#ifndef FILE_API_H_
#define FILE_API_H_

#include <sys/types.h>

#include "file_lib.h"

#define     ENABLE_FILE_TYPE_IDENTIFICATION      0x1
#define     ENABLE_FILE_SIGNATURE_SHA256         0x2
#define     FILE_ALL_ON                          0xFFFFFFFF
#define     FILE_ALL_OFF                         0x00000000


typedef enum _File_Verdict
{
    FILE_VERDICT_UNKNOWN,
    FILE_VERDICT_LOG,
    FILE_VERDICT_STOP,
    FILE_VERDICT_BLOCK
} File_Verdict;

#define FILE_API_VERSION5 1

typedef uint32_t (*Get_file_policy_func) (void* ssnptr, int16_t app_id, bool upload);
typedef File_Verdict (*File_type_done_func) (void* ssnptr, uint32_t file_type_id, bool upload);
typedef File_Verdict (*File_signature_done_func) (void* ssnptr, uint8_t* file_sig, bool upload);

typedef int (*File_process_func)( void* p, uint8_t* file_data, int data_size, FilePosition position, bool upload);
typedef int (*Get_file_name_func) (void* ssnptr, uint8_t **file_name, uint32_t *name_len);
typedef uint64_t (*Get_file_size_func) (void* ssnptr);
typedef bool (*Get_file_direction_func) (void* ssnptr);
typedef uint8_t *(*Get_file_sig_sha256_func) (void* ssnptr);

typedef void (*Set_file_name_func) (void* ssnptr, uint8_t *, uint32_t);
typedef void (*Set_file_direction_func) (void* ssnptr, bool);

typedef int64_t (*Get_file_depth_func) (void);

typedef void (*Enable_file_type_func)(Get_file_policy_func , File_type_done_func   );
typedef void (*Enable_file_signature_func)(Get_file_policy_func , File_signature_done_func );


typedef struct _file_api
{
    int version;

    /*File process function, called by preprocessors that provides file data*/
    File_process_func file_process;

    /*File properties*/
    Get_file_name_func get_file_name;
    Get_file_size_func get_file_size;
    Get_file_size_func get_file_processed_size;
    Get_file_direction_func get_file_direction;
    Get_file_sig_sha256_func get_sig_sha256;
    Set_file_name_func set_file_name;
    Set_file_direction_func set_file_direction;
    /*File call backs*/
    Enable_file_type_func enable_file_type;
    Enable_file_signature_func enable_file_signature;

    /*File configurations*/
    Get_file_depth_func get_max_file_depth;

} FileAPI;

/* To be set by Stream5 */
extern FileAPI *file_api;

static inline void initFilePosition(FilePosition *position, uint64_t processed_size)
{
    *position = SNORT_FILE_START;
    if (processed_size)
        *position = SNORT_FILE_MIDDLE;
}
static inline void updateFilePosition(FilePosition *position, uint64_t processed_size)
{
    if ((*position == SNORT_FILE_END) || (*position == SNORT_FILE_FULL))
        *position = SNORT_FILE_START;
    else if (processed_size)
        *position = SNORT_FILE_MIDDLE;
}
static inline void finalFilePosition(FilePosition *position)
{
    if (*position == SNORT_FILE_START)
        *position = SNORT_FILE_FULL;
    else if (*position != SNORT_FILE_FULL)
        *position = SNORT_FILE_END;
}
#endif /* FILE_API_H_ */


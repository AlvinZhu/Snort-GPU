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

// @file    shmem_datamgmt.h
// @author  Pramod Chandrashekar <pramod@sourcefire.com>

#ifndef _SHMEM_DMGMT_H_
#define _SHMEM_DMGMT_H_

#include <stdint.h>
#include "sf_types.h"

#define SF_EINVAL  1
#define SF_SUCCESS 0
#define SF_ENOMEM  2
#define SF_EEXIST  3

#define MAX_NAME  1024  

#define FILE_LIST_BUCKET_SIZE     100
#define MAX_NUM_ZONES             1052
#define MAX_MANIFEST_LINE_LENGTH  8*MAX_NUM_ZONES
#define MAX_LIST_ID               UINT32_MAX
#define MAX_IPLIST_FILES          255

typedef struct _FileList
{
    char*    filename;
    int      filetype;
    uint32_t      listid;
    bool zones[MAX_NUM_ZONES];
} ShmemDataFileList;

extern ShmemDataFileList** filelist_ptr;
extern int file_count;

int GetSortedListOfShmemDataFiles(void);
int GetLatestShmemDataSetVersionOnDisk(uint32_t* shmemVersion);
void FreeShmemDataFileList(void);
void PrintDataFiles(void);
void PrintListInfo (bool *zones, uint32_t listid);
#endif


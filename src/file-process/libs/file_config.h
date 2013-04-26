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
**  5.25.2012 - Initial Source Code. Hcao
*/
#ifndef __FILE_CONFIG_H__
#define __FILE_CONFIG_H__
#include "file_lib.h"
#include "file_identifier.h"

#define FILE_ID_MAX          1024

typedef struct _IdentifierMemoryBlock
{
    void *mem_block;  /*the node that is shared*/
    struct _IdentifierMemoryBlock *next;  /*next node*/
}IdentifierMemoryBlock;

typedef struct _fileConfig
{
    IdentifierNode *identifier_root; /*Root of magic tries*/
    IdentifierMemoryBlock *id_memory_root; /*root of memory used*/
    RuleInfo *FileRules[FILE_ID_MAX + 1];
    int64_t file_type_depth;
    int64_t file_signature_depth;
#if defined(DEBUG_MSGS) || defined (REG_TEST)
    int64_t show_data_depth;
#endif
} FileConfig;
FileConfig *get_file_config(void **file_config);
void parse_file_rule(char *args, void **file_config);
RuleInfo *get_rule_from_id(void *conf, uint32_t);
void free_file_rules(void*);
#endif


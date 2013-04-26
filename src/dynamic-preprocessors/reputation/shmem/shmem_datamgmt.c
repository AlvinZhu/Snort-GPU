/* $Id$ */
/****************************************************************************
 *
 * Copyright (C) 2005-2013 Sourcefire, Inc.
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

// @file    shmem_datamgmt.c
// @author  Pramod Chandrashekar <pramod@sourcefire.com>

#include <dirent.h>
#include <limits.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>

#include "shmem_config.h"
#include "shmem_common.h"

#define MANIFEST_SEPARATORS         ",\r\n"
#define MIN_MANIFEST_COLUMNS         3

#define WHTITE_TYPE_KEYWORD       "white"
#define BLACK_TYPE_KEYWORD        "block"
#define MONITOR_TYPE_KEYWORD      "monitor"


static const char* const MODULE_NAME = "ShmemFileMgmt";

// FIXTHIS eliminate these globals
ShmemDataFileList **filelist_ptr = NULL;
int file_count = 0;

static int StringCompare(const void *elem1, const void *elem2)
{
    ShmemDataFileList * const *a = elem1;
    ShmemDataFileList * const *b = elem2;

    return strcmp((*a)->filename,(*b)->filename);
}

static int AllocShmemDataFileList()
{
    if ((filelist_ptr = (ShmemDataFileList**)
            realloc(filelist_ptr,(file_count + FILE_LIST_BUCKET_SIZE)*
                    sizeof(ShmemDataFileList*))) == NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_REPUTATION,
                "Cannot allocate memory to store shmem data files\n"););
        return SF_ENOMEM;
    }
    return SF_SUCCESS;
}

static void FreeShmemDataFileListFiles()
{
    int i;

    if (!filelist_ptr)
        return;

    for(i = 0; i < file_count ; i++)
    {
        free(filelist_ptr[i]->filename);
        free(filelist_ptr[i]);
    }
    file_count = 0;
}

static int ReadShmemDataFilesWithoutManifest()
{
    char   filename[PATH_MAX];
    struct dirent *de;
    DIR    *dd;
    int    max_files  = MAX_IPLIST_FILES;
    char   *ext_end   = NULL;
    int    type       = 0;
    int    counter    = 0;
    int    startup    = 1;

    FreeShmemDataFileListFiles();

    if ((dd = opendir(shmusr_ptr->path)) == NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_REPUTATION,
                "Could not open %s to read IPRep data files\n",shmusr_ptr->path););
        return SF_EINVAL;
    }
    while ((de = readdir(dd)) != NULL && max_files)
    {
        //DEBUG_WRAP(DebugMessage(DEBUG_REPUTATION, "Files are %s\n",de->d_name););
        if (strstr(de->d_name, ".blf") || strstr(de->d_name, ".wlf"))
        {
            //no need to check for NULL, established there is a period in strstr
            ext_end = (char*)strrchr(de->d_name,'.'); 

            if (strncasecmp(ext_end,".blf",4) == 0)
                type = BLACK_LIST;
            else if (strncasecmp(ext_end,".wlf",4) == 0)
                type = WHITE_LIST;

            if (type == 0) continue;

            counter++;

            if (startup || counter == FILE_LIST_BUCKET_SIZE)
            {
                startup=0;
                counter=0;
                if (AllocShmemDataFileList())
                    return SF_ENOMEM;
            }    

            if ((filelist_ptr[file_count] = (ShmemDataFileList*)
                    malloc(sizeof(ShmemDataFileList))) == NULL)
            {
                DEBUG_WRAP(DebugMessage(DEBUG_REPUTATION,
                        "Cannot allocate memory to store file information\n"););
                return SF_ENOMEM;
            }
            snprintf(filename, sizeof(filename), "%s/%s", shmusr_ptr->path,de->d_name);
            filelist_ptr[file_count]->filename = strdup(filename);
            filelist_ptr[file_count]->filetype = type;
            filelist_ptr[file_count]->listid = 0;
            memset(filelist_ptr[file_count]->zones, true, MAX_NUM_ZONES);
            max_files--;
            file_count++;
            type = 0;
        }
    }
    closedir(dd);
    return SF_SUCCESS;
}

/*Ignore the space characters from string*/
static char *ignoreStartSpace(char *str)
{
    while((*str) && (isspace((int)*str)))
    {
        str++;
    }
    return str;
}

/*Get file type */
static int getFileTypeFromName (char *typeName)
{
    int type = UNKNOW_LIST;

    /* Trim the starting spaces */
    if (!typeName)
        return type;

    typeName = ignoreStartSpace(typeName);

    if (strncasecmp(typeName, WHTITE_TYPE_KEYWORD, strlen(WHTITE_TYPE_KEYWORD)) == 0)
    {
        type = WHITE_LIST;
        typeName += strlen(WHTITE_TYPE_KEYWORD);
    }
    else if (strncasecmp(typeName, BLACK_TYPE_KEYWORD, strlen(BLACK_TYPE_KEYWORD)) == 0)
    {
        type = BLACK_LIST;
        typeName += strlen(BLACK_TYPE_KEYWORD);
    }
    else if (strncasecmp(typeName, MONITOR_TYPE_KEYWORD, strlen(MONITOR_TYPE_KEYWORD)) == 0)
    {
        type = MONITOR_LIST;
        typeName += strlen(MONITOR_TYPE_KEYWORD);
    }

    if (UNKNOW_LIST != type )
    {
        /*Ignore spaces in the end*/
        typeName = ignoreStartSpace(typeName);

        if ( *typeName )
        {
            type = UNKNOW_LIST;
        }

    }

    return type;

}

/*  Parse the line item in manifest file
 *
 *  The format of manifest is:
 *    file_name, list_id, action (block, white, monitor), zone information
 *
 *  If no zone information provided, this means all zones are applied.
 *
 * */

static ShmemDataFileList* processLineInManifest(char *manifest, char *line, int linenumber)
{
    char* token;
    int tokenIndex = 0;
    ShmemDataFileList* listItem = NULL;
    char* nextPtr = line;
    char filename[PATH_MAX];
    bool hasZone = false;

    if ((listItem = (ShmemDataFileList*)calloc(1,sizeof(ShmemDataFileList))) == NULL)
    {
        DynamicPreprocessorFatalMessage("%s(%d) => Cannot allocate memory to "
                "store reputation manifest file information\n", manifest, linenumber);
        return NULL;
    }

    while((token = strtok_r(nextPtr, MANIFEST_SEPARATORS, &nextPtr)) != NULL)
    {
        char *endStr;
        long zone_id;
        long list_id;


        DEBUG_WRAP(DebugMessage(DEBUG_REPUTATION, "Process reputation list token: %s\n",token ););

        switch (tokenIndex)
        {
        case 0:    /* File name */
            DEBUG_WRAP(DebugMessage(DEBUG_REPUTATION, "Reputation list filename: %s\n",token ););
            snprintf(filename, sizeof(filename), "%s/%s", shmusr_ptr->path,token);
            listItem->filename = strdup(filename);
            if (listItem->filename == NULL)
            {
                DynamicPreprocessorFatalMessage("%s(%d) => Failed to allocate memory for "
                        "reputation manifest\n", manifest, linenumber);
            }
            break;

        case 1:    /* List ID */

            list_id = _dpd.SnortStrtol( token, &endStr, 10);

            /*Ignore spaces in the end*/
            endStr = ignoreStartSpace(endStr);

            if ( *endStr )
            {
                DynamicPreprocessorFatalMessage("%s(%d) => Bad value (%s) specified for listID. "
                        "Please specify an integer between %d and %li.\n",
                        manifest, linenumber, token, 0, MAX_LIST_ID);
            }

            if ((list_id < 0)  || (list_id > MAX_LIST_ID) || (errno == ERANGE))
            {
                DynamicPreprocessorFatalMessage(" %s(%d) => Value specified (%s) is out of "
                        "bounds.  Please specify an integer between %d and %li.\n",
                        manifest, linenumber, token, 0, MAX_LIST_ID);
            }
            listItem->listid = (uint32_t) list_id;
            break;

        case 2:    /* Action */
            listItem->filetype = getFileTypeFromName(token);
            if (UNKNOW_LIST == listItem->filetype)
            {
                DynamicPreprocessorFatalMessage(" %s(%d) => Unknown action specified (%s)."
                        " Please specify a value: %s | %s | %s.\n", manifest, linenumber, token,
                        WHTITE_TYPE_KEYWORD, BLACK_TYPE_KEYWORD, MONITOR_TYPE_KEYWORD);
            }
            break;

        default:

            /*Ignore spaces in the beginning*/
            token= ignoreStartSpace(token);
            if (!(*token))
               break;

            zone_id = _dpd.SnortStrtol( token, &endStr, 10);

            /*Ignore spaces in the end*/
            endStr = ignoreStartSpace(endStr);

            if ( *endStr)
            {
                DynamicPreprocessorFatalMessage("%s(%d) => Bad value (%s) specified for zone. "
                        "Please specify an integer between %d and %li.\n",
                        manifest, linenumber, token, 0, MAX_NUM_ZONES - 1);
            }
            if ((zone_id < 0)  || (zone_id >= MAX_NUM_ZONES ) || (errno == ERANGE))
            {
                DynamicPreprocessorFatalMessage(" %s(%d) => Value specified (%s) for zone is "
                        "out of bounds.  Please specify an integer between %d and %li.\n",
                        manifest, linenumber, token, 0, MAX_NUM_ZONES - 1);
            }

            listItem->zones[zone_id] = true;
            hasZone = true;
        }
        tokenIndex++;
    }

    if (tokenIndex < MIN_MANIFEST_COLUMNS)
    {
        /* Too few columns*/
        free(listItem);
        if (tokenIndex)
        {
            DynamicPreprocessorFatalMessage("%s(%d) => Too few columns in line: %s.\n ",
                    manifest, linenumber, line);
        }
        return NULL;
    }

    if (false == hasZone)
    {
        memset(listItem->zones, true, MAX_NUM_ZONES);
    }
    return listItem;
}

/*Parse the manifest file*/
static int ReadShmemDataFilesWithManifest()
{
    FILE *fp;
    char line[MAX_MANIFEST_LINE_LENGTH];
    char manifest_file[PATH_MAX];
    int  counter  = 0;
    int  startup    = 1;
    int  line_number = 0;

    snprintf(manifest_file, sizeof(manifest_file),
            "%s/%s",shmusr_ptr->path, MANIFEST_FILENAME);

    if ((fp = fopen(manifest_file, "r")) == NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_REPUTATION,
                "Error opening file at: %s\n", manifest_file););
        return NO_FILE;
    }

    FreeShmemDataFileListFiles();

    while (fgets(line, sizeof(line),fp))
    {
        char* nextPtr = NULL;
        ShmemDataFileList* listItem;

        line_number++;

        DEBUG_WRAP(DebugMessage(DEBUG_REPUTATION, "Reputation manifest: %s\n",line ););
        /* remove comments */
        if((nextPtr = strchr(line, '#')) != NULL)
        {
            *nextPtr = '\0';
        }

        /* allocate memory if necessary*/
        counter++;

        if (startup || counter == FILE_LIST_BUCKET_SIZE)
        {
            startup=0;
            counter=0;
            if (AllocShmemDataFileList())
                return SF_ENOMEM;
        }

        /*Processing the line*/
        listItem = processLineInManifest(manifest_file, line, line_number);

        if (listItem)
        {
            filelist_ptr[file_count] = listItem;
            if (file_count > MAX_IPLIST_FILES -1)
                break;
            file_count++;

        }

    }

    fclose(fp);

    DEBUG_WRAP(DebugMessage(DEBUG_REPUTATION,
            "Successfully processed manifest file: %s\n", MANIFEST_FILENAME););

    return SF_SUCCESS;
}

int GetSortedListOfShmemDataFiles()
{
    int rval;

    if ((rval = ReadShmemDataFilesWithManifest()) == NO_FILE)
    {
        if ((rval = ReadShmemDataFilesWithoutManifest()) != SF_SUCCESS)
            return rval;

        qsort(filelist_ptr,file_count,sizeof(*filelist_ptr),StringCompare);
    }
    return rval;
}    

//valid version values are 1 through UINT_MAX
int GetLatestShmemDataSetVersionOnDisk(uint32_t* shmemVersion)
{
    unsigned long tmpVersion;
    FILE *fp;
    char line[PATH_MAX];
    char version_file[PATH_MAX];
    const char *const key = "VERSION"; 
    char* keyend_ptr      = NULL;

    snprintf(version_file, sizeof(version_file),
            "%s/%s",shmusr_ptr->path,VERSION_FILENAME);

    if ((fp = fopen(version_file, "r")) == NULL)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_REPUTATION,
                "Error opening file at: %s\n", version_file););
        return NO_FILE;
    }

    while (fgets(line,sizeof(line),fp))
    {
        char *strptr;
        if ( !strncmp(line,"#",1) )
            continue;
        if ( (strptr = strstr(line, key )) && (strptr == line) )
        {
            keyend_ptr  = line;
            keyend_ptr += strlen(key) + 1;
            tmpVersion  = strtoul(keyend_ptr,NULL,0);
            break;
        }
    }   

    if (!keyend_ptr)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_REPUTATION,
                "Invalid file format %s\n", version_file););
        return NO_FILE;
    }    

    if (tmpVersion > UINT_MAX) //someone tampers with the file
        *shmemVersion = 1; 
    else 
        *shmemVersion = (uint32_t)tmpVersion;

    fclose(fp);

    DEBUG_WRAP(DebugMessage(DEBUG_REPUTATION,
            "version information being returned is %u\n", *shmemVersion););

    return SF_SUCCESS;
}    

void PrintListInfo (bool *zones, uint32_t listid)
{
    char zonesInfo[MAX_MANIFEST_LINE_LENGTH];
    int zone_id;

    int buf_len = sizeof(zonesInfo);
    char *out_buf = zonesInfo;
    for (zone_id = 0; zone_id < MAX_NUM_ZONES; zone_id++)
    {
        int bytesOutput;

        if (!zones[zone_id])
            continue;

        bytesOutput = snprintf(out_buf, buf_len, "%d,",zone_id);
        out_buf += bytesOutput;
        buf_len -= bytesOutput;

    }
    DEBUG_WRAP(DebugMessage(DEBUG_REPUTATION,
                        "List %li has zones defined: %s \n", listid, zonesInfo););
}

void PrintDataFiles()
{
    int i;

    for (i=0;i< file_count;i++)
    {
        DEBUG_WRAP(DebugMessage(DEBUG_REPUTATION,
                "File %s of type %d found \n",
                filelist_ptr[i]->filename, filelist_ptr[i]->filetype););
        if (filelist_ptr[i]->listid)
        {
            PrintListInfo(filelist_ptr[i]->zones, filelist_ptr[i]->listid);
        }
    }

}

void FreeShmemDataFileList()
{
    FreeShmemDataFileListFiles();
    free(filelist_ptr);
    return;
}


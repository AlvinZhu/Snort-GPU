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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>

#include "sf_types.h"
#include "util.h"
#include "mstring.h"
#include "parser.h"

#include "file_service_config.h"
#include "file_config.h"
#include "file_lib.h"


#define FILE_SERVICE_OPT__TYPE_DEPTH        "file_type_depth"
#define FILE_SERVICE_OPT__SIG_DEPTH         "file_signature_depth"

#define FILE_SERVICE_TYPE_DEPTH_MIN    0
#define FILE_SERVICE_TYPE_DEPTH_MAX    UINT32_MAX
#define FILE_SERVICE_SIG_DEPTH_MIN    0
#define FILE_SERVICE_SIG_DEPTH_MAX    UINT32_MAX

#if defined(DEBUG_MSGS) || defined (REG_TEST)
#define FILE_SERVICE_OPT__TYPE              "type_id"
#define FILE_SERVICE_OPT__SIG               "signature"
#define FILE_SERVICE_OPT__SHOW_DATA_DEPTH   "show_data_depth"
#include "file_api.h"
#endif
/*The main function for parsing rule option*/
void file_service_config(char *args, void **conf)
{
    char **toks;
    int num_toks;
    int i;
    FileConfig *file_config = get_file_config(conf);

    DEBUG_WRAP(DebugMessage(DEBUG_FILE,"Loading file service configuration: %s\n", args););

    if (!file_config)
    {
        return;
    }

    toks = mSplit(args, ",", 0, &num_toks, 0);  /* get rule option pairs */

    for (i = 0; i < num_toks; i++)
    {
        char **opts;
        int num_opts;
        char *option_args = NULL;

        DEBUG_WRAP(DebugMessage(DEBUG_FILE,"   option: %s\n", toks[i]););

        /* break out the option name from its data */
        opts = mSplit(toks[i], " ", 2, &num_opts, '\\');

        DEBUG_WRAP(DebugMessage(DEBUG_FILE,"   option name: %s\n", opts[0]););

        if (num_opts == 2)
        {
            option_args = opts[1];
            DEBUG_WRAP(DebugMessage(DEBUG_FILE,"   option args: %s\n", option_args););
        }
        if ( !strcasecmp( opts[0], FILE_SERVICE_OPT__TYPE_DEPTH ))
        {
            long int value;
            char *endptr;

            if (option_args == NULL)
                ParseError("%s rule option requires an argument.",
                        FILE_SERVICE_OPT__TYPE_DEPTH );

            value = SnortStrtol(option_args, &endptr, 0);
            if ((errno == ERANGE) || (*endptr != '\0') ||
                    (value > FILE_SERVICE_TYPE_DEPTH_MAX) ||(value < FILE_SERVICE_TYPE_DEPTH_MIN) )
            {
                ParseError("Bad value specified for %s. Please specify an integer between %u and %u",
                        FILE_SERVICE_OPT__TYPE_DEPTH, FILE_SERVICE_TYPE_DEPTH_MIN, FILE_SERVICE_TYPE_DEPTH_MAX);
            }
            if (value == 0)
                value = FILE_SERVICE_TYPE_DEPTH_MAX;

            file_config->file_type_depth = value;

        }
        else if ( !strcasecmp( opts[0], FILE_SERVICE_OPT__SIG_DEPTH ))
        {
            long int value;
            char *endptr;

            if (option_args == NULL)
                ParseError("%s rule option requires an argument.",
                        FILE_SERVICE_OPT__SIG_DEPTH );

            value = SnortStrtol(option_args, &endptr, 0);
            if ((errno == ERANGE) || (*endptr != '\0') ||
                    (value > FILE_SERVICE_SIG_DEPTH_MAX) ||(value < FILE_SERVICE_SIG_DEPTH_MIN) )
            {
                ParseError("Bad value specified for %s. Please specify an integer between %u and %u",
                        FILE_SERVICE_OPT__SIG_DEPTH, FILE_SERVICE_SIG_DEPTH_MIN, FILE_SERVICE_SIG_DEPTH_MAX);
            }
            if (value == 0)
                value = FILE_SERVICE_SIG_DEPTH_MAX;

            file_config->file_signature_depth = value;
        }
#if defined(DEBUG_MSGS) || defined (REG_TEST)
        else if ( !strcasecmp( opts[0], FILE_SERVICE_OPT__TYPE ))
        {
            file_api->enable_file_type(NULL, NULL);

        }
        else if ( !strcasecmp( opts[0], FILE_SERVICE_OPT__SIG ))
        {
            file_api->enable_file_signature(NULL, NULL);
        }
        else if ( !strcasecmp( opts[0], FILE_SERVICE_OPT__SHOW_DATA_DEPTH ))
        {
            long int value;
            char *endptr;

            if (option_args == NULL)
                ParseError("%s rule option requires an argument.",
                        FILE_SERVICE_OPT__SHOW_DATA_DEPTH );

            value = SnortStrtol(option_args, &endptr, 0);
            if ((errno == ERANGE) || (*endptr != '\0') ||
                    (value > FILE_SERVICE_SIG_DEPTH_MAX) ||(value < FILE_SERVICE_SIG_DEPTH_MIN) )
            {
                ParseError("Bad value specified for %s. Please specify an integer between %u and %u",
                        FILE_SERVICE_OPT__SHOW_DATA_DEPTH, FILE_SERVICE_SIG_DEPTH_MIN, FILE_SERVICE_SIG_DEPTH_MAX);
            }

            file_config->show_data_depth = value;
        }
#endif
        else
        {
            ParseError("Invalid argument: %s\n",  opts[0]);
            return;
        }
        mSplitFree(&opts, num_opts);
    }

    mSplitFree(&toks, num_toks);
}


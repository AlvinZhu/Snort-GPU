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

#ifndef __FILE_SERVICE_H__
#define __FILE_SERVICE_H__


/*
 * Generator id. Define here the same as the official registry
 * in generators.h
 */
#define GENERATOR_FILE_TYPE        146
#define GENERATOR_FILE_SIGNATURE   147

#define FILE_SIGNATURE_SHA256        1
#define FILE_SIGNATURE_SHA256_STR       "(file) malware detected"

void FileAPIInit(void);
void FreeFileConfig(void*);
#endif


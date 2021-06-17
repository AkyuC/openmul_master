/*
 *  fsync.h: File syncing function headers
 *  Copyright (C) 2012, Dipjyoti Saikia <dipjyoti.saikia@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#ifndef __FSYNC_H__
#define __FSYNC_H__

#define FSYNC_SERVER_PORT 10002 
#define FSYNC_CLIENT_PORT 10006 
#define MAX_FLINE 512 
#define MAX_BLK_SIZE 512

#define ACK                   2
#define NACK                  3
#define REQUESTFILE           100
#define SENDFILE              110
#define COMMANDNOTSUPPORTED   150
#define COMMANDSUPPORTED      160
#define BADFILENAME           200
#define FILENAMEOK            400
#define STARTTRANSFER         500

int fsync_server_start(void);
int c_fsync(const char *fname, const char *server_ip, uint16_t port);
int c_fsync_dir(const char *dir, const char *server_ip, uint16_t port);

#endif

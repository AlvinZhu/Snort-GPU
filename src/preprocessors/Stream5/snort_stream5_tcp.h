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

#ifndef STREAM5_TCP_H_
#define STREAM5_TCP_H_

#include "stream5_common.h"
#include "sfPolicy.h"

extern uint32_t xtradata_func_count;
extern LogFunction xtradata_map[LOG_FUNC_MAX];
extern LogExtraData extra_data_log;
extern void *extra_data_config;

void Stream5CleanTcp(void);
void Stream5ResetTcp(void);
void Stream5InitTcp(Stream5GlobalConfig *);
void Stream5TcpRegisterPreprocProfiles(void);
void Stream5TcpRegisterRuleOptions(void);
void Stream5TcpInitFlushPoints(void);
int Stream5VerifyTcpConfig(Stream5TcpConfig *, tSfPolicyId);
void Stream5TcpPolicyInit(Stream5TcpConfig *, char *);
int Stream5ProcessTcp(Packet *, Stream5LWSession *,
                      Stream5TcpPolicy *, SessionKey *);
int Stream5FlushListener(Packet *p, Stream5LWSession *lwssn);
int Stream5FlushTalker(Packet *p, Stream5LWSession *lwssn);
int Stream5FlushClient(Packet *p, Stream5LWSession *lwssn);
int Stream5FlushServer(Packet *p, Stream5LWSession *lwssn);
void TcpUpdateDirection(Stream5LWSession *ssn, char dir,
                        snort_ip_p ip, uint16_t port);
void Stream5TcpBlockPacket(Packet *p);
Stream5LWSession *GetLWTcpSession(SessionKey *key);
int GetTcpRebuiltPackets(Packet *p, Stream5LWSession *ssn,
        PacketIterator callback, void *userdata);
int GetTcpStreamSegments(Packet *p, Stream5LWSession *ssn,
        StreamSegmentIterator callback, void *userdata);
int Stream5AddSessionAlertTcp(Stream5LWSession *lwssn, Packet *p, uint32_t gid, uint32_t sid, int alerted);
int Stream5CheckSessionAlertTcp(Stream5LWSession *lwssn, Packet *p, uint32_t gid, uint32_t sid);
int Stream5LogSessionAlertExtraDataTcp(Stream5LWSession *lwssn, Packet *p, uint32_t gid, uint32_t sid, uint32_t event_id, uint32_t event_second);
char Stream5GetReassemblyDirectionTcp(Stream5LWSession *lwssn);
uint32_t Stream5GetFlushPointTcp(Stream5LWSession *lwssn, char dir);
void Stream5SetFlushPointTcp(Stream5LWSession *lwssn, char dir, uint32_t flush_point);
char Stream5SetReassemblyTcp(Stream5LWSession *lwssn, uint8_t flush_policy, char dir, char flags);
char Stream5GetReassemblyFlushPolicyTcp(Stream5LWSession *lwssn, char dir);
char Stream5IsStreamSequencedTcp(Stream5LWSession *lwssn, char dir);
int Stream5MissingInReassembledTcp(Stream5LWSession *lwssn, char dir);
char Stream5PacketsMissingTcp(Stream5LWSession *lwssn, char dir);
void s5TcpSetPortFilterStatus(
        unsigned short port,
        uint16_t status,
        tSfPolicyId policyId,
        int parsing
        );
void s5TcpUnsetPortFilterStatus(
        unsigned short port,
        uint16_t status,
        tSfPolicyId policyId,
        int parsing
        );
int s5TcpGetPortFilterStatus(
        unsigned short port,
        tSfPolicyId policyId,
        int parsing
        );
void s5TcpSetSynSessionStatus(uint16_t status, tSfPolicyId policyId, int parsing);
void s5TcpUnsetSynSessionStatus(uint16_t status, tSfPolicyId policyId, int parsing);
void Stream5TcpConfigFree(Stream5TcpConfig *);
void** Stream5GetPAFUserDataTcp(Stream5LWSession*, bool to_server);
bool Stream5IsPafActiveTcp(Stream5LWSession*, bool to_server);
bool Stream5ActivatePafTcp(Stream5LWSession*, bool to_server);

uint32_t Stream5GetTcpPrunes(void);
void Stream5ResetTcpPrunes(void);

#ifdef NORMALIZER
void Stream_PrintNormalizationStats(void);
void Stream_ResetNormalizationStats(void);
#endif

#ifdef ENABLE_PAF
void Stream5PostConfigTcp(void*);
#endif

#endif /* STREAM5_TCP_H_ */

#ifndef ICE_AGENT_APIS_H
#define ICE_AGENT_APIS_H

/* Standard includes. */
#include <stdint.h>
#include <stddef.h>

#define ICE_CANDIDATE_ID_LEN                    8

#define KVS_ICE_MAX_LOCAL_CANDIDATE_COUNT       100
#define KVS_ICE_MAX_REMOTE_CANDIDATE_COUNT      100
#define KVS_ICE_MAX_CANDIDATE_PAIR_COUNT        1024
#define MAX_ICE_SERVERS_COUNT                   21

/* ICE candidate priorities */
#define ICE_PRIORITY_HOST_CANDIDATE_TYPE_PREFERENCE             126
#define ICE_PRIORITY_SERVER_REFLEXIVE_CANDIDATE_TYPE_PREFERENCE 100
#define ICE_PRIORITY_PEER_REFLEXIVE_CANDIDATE_TYPE_PREFERENCE   110
#define ICE_PRIORITY_RELAYED_CANDIDATE_TYPE_PREFERENCE          0
#define ICE_PRIORITY_LOCAL_PREFERENCE                           65535


typedef enum {
    ICE_CANDIDATE_TYPE_HOST = 0,
    ICE_CANDIDATE_TYPE_PEER_REFLEXIVE = 1,
    ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE = 2,
    ICE_CANDIDATE_TYPE_RELAYED = 3,
} IceCandidateType_t;

typedef enum {
    ICE_CANDIDATE_STATE_NEW,
    ICE_CANDIDATE_STATE_VALID,
    ICE_CANDIDATE_STATE_INVALID,
} IceCandidateState_t;

typedef enum {
    ICE_CANDIDATE_PAIR_STATE_FROZEN = 0,
    ICE_CANDIDATE_PAIR_STATE_WAITING = 1,
    ICE_CANDIDATE_PAIR_STATE_IN_PROGRESS = 2,
    ICE_CANDIDATE_PAIR_STATE_SUCCEEDED = 3,
    ICE_CANDIDATE_PAIR_STATE_FAILED = 4,
} IceCandidatePairState_t;

typedef enum {
    ICE_SOCKET_PROTOCOL_NONE,
    ICE_SOCKET_PROTOCOL_TCP,
    ICE_SOCKET_PROTOCOL_UDP,
} IceSocketProtocol_t;

typedef enum IceResult
{
    ICE_RESULT_OK,
    ICE_RESULT_BASE = 0x53000000,
    ICE_RESULT_BAD_PARAM,
    ICE_RESULT_MAX_CANDIDATE_THRESHOLD,
    ICE_RESULT_MAX_CANDIDATE_PAIR_THRESHOLD,
    ICE_RESULT_OUT_OF_MEMORY,
    ICE_RESULT_SPRINT_ERROR
} IceResult_t;

/* ICE component structures */

typedef struct IceIPAddress
{
    uint16_t family;
    uint16_t port;
    uint8_t address[16];
    uint32_t isPointToPoint;
} IceIPAddress_t;

typedef struct TransactionIdStore
{
    uint32_t maxTransactionIdsCount;
    uint32_t nextTransactionIdIndex;
    uint32_t earliestTransactionIdIndex;
    uint32_t transactionIdCount;
    uint8_t * transactionIds;
} TransactionIdStore_t;

typedef struct IceServer
{
    char url[MAX_ICE_CONFIG_URI_LEN + 1];
    char username[MAX_ICE_CONFIG_USER_NAME_LEN + 1];
    char credential[MAX_ICE_CONFIG_CREDENTIAL_LEN + 1];
    IceSocketProtocol_t transport;
    IceIPAddress_t ipAddress;
    uint8_t IceServerAttributeFlag;
} IceServer_t;

typedef struct IceCandidate
{
    IceCandidateType_t iceCandidateType;
    uint32_t isRemote;
    IceIPAddress_t ipAddress;
    IceCandidateState_t state;
    uint32_t priority;
    IceSocketProtocol_t remoteProtocol;
} IceCandidate_t;

typedef struct IceCandidatePair
{
    IceCandidate_t* local;
    IceCandidate_t* remote;
    uint32_t nominated;
    uint64_t priority;
    IceCandidatePairState_t state;
} IceCandidatePair_t;

typedef struct IceAgent
{
    IceCandidate_t* localCandidates[ KVS_ICE_MAX_LOCAL_CANDIDATE_COUNT ];
    IceCandidate_t* remoteCandidates[ KVS_ICE_MAX_REMOTE_CANDIDATE_COUNT ];
    IceServer_t* iceServers[ MAX_ICE_SERVERS_COUNT ];
    uint32_t iceServersCount;
    IceCandidatePair_t* iceCandidatePairs[ KVS_ICE_MAX_CANDIDATE_PAIR_COUNT ];
    uint32_t isControlling;
    uint64_t tieBreaker;
    TransactionIdStore_t* pStunBindingRequestTransactionIdStore;
} IceAgent_t;



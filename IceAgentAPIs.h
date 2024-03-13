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

#define IPV6_ADDRESS_LENGTH (uint16_t) 16
#define IPV4_ADDRESS_LENGTH (uint16_t) 4

/* ICE candidate priorities */
#define ICE_PRIORITY_HOST_CANDIDATE_TYPE_PREFERENCE             126
#define ICE_PRIORITY_SERVER_REFLEXIVE_CANDIDATE_TYPE_PREFERENCE 100
#define ICE_PRIORITY_PEER_REFLEXIVE_CANDIDATE_TYPE_PREFERENCE   110
#define ICE_PRIORITY_RELAYED_CANDIDATE_TYPE_PREFERENCE          0
#define ICE_PRIORITY_LOCAL_PREFERENCE                           65535

/* STUN headers */
#define STUN_HEADER_MAGIC_COOKIE                    (uint32_t) 0x2112A442
#define STUN_PACKET_TYPE_BINDING_REQUEST            (uint16_t) 0x0001
#define STUN_PACKET_TYPE_BINDING_RESPONSE_SUCCESS   (uint16_t) 0x0101


typedef enum {
    ICE_CANDIDATE_TYPE_HOST = 0,
    ICE_CANDIDATE_TYPE_PEER_REFLEXIVE = 1,
    ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE = 2,
    ICE_CANDIDATE_TYPE_RELAYED = 3,
} ICE_CANDIDATE_TYPE;

typedef enum {
    ICE_CANDIDATE_STATE_NEW,
    ICE_CANDIDATE_STATE_VALID,
    ICE_CANDIDATE_STATE_INVALID,
} ICE_CANDIDATE_STATE;

typedef enum {
    ICE_CANDIDATE_PAIR_STATE_FROZEN = 0,
    ICE_CANDIDATE_PAIR_STATE_WAITING = 1,
    ICE_CANDIDATE_PAIR_STATE_IN_PROGRESS = 2,
    ICE_CANDIDATE_PAIR_STATE_SUCCEEDED = 3,
    ICE_CANDIDATE_PAIR_STATE_FAILED = 4,
} ICE_CANDIDATE_PAIR_STATE;

typedef enum {
    KVS_SOCKET_PROTOCOL_NONE,
    KVS_SOCKET_PROTOCOL_TCP,
    KVS_SOCKET_PROTOCOL_UDP,
} KVS_SOCKET_PROTOCOL;

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

typedef struct {
    uint16_t family;
    uint16_t port;
    uint8_t address[IPV6_ADDRESS_LENGTH];
    uint32_t isPointToPoint;
} KvsIpAddress, *PKvsIpAddress;

typedef struct {
    uint32_t maxTransactionIdsCount;
    uint32_t nextTransactionIdIndex;
    uint32_t earliestTransactionIdIndex;
    uint32_t transactionIdCount;
    uint8_t * transactionIds;
} TransactionIdStore_t;

typedef struct {
    bool isTurn;
    bool isSecure;
    char url[MAX_ICE_CONFIG_URI_LEN + 1];
    KvsIpAddress ipAddress;
    char username[MAX_ICE_CONFIG_USER_NAME_LEN + 1];
    char credential[MAX_ICE_CONFIG_CREDENTIAL_LEN + 1];
    KVS_SOCKET_PROTOCOL transport;
    KvsIpAddress ipAddress;
} IceServer_t;

typedef struct {
    ICE_CANDIDATE_TYPE iceCandidateType;
    uint32_t isRemote;
    KvsIpAddress ipAddress;
    ICE_CANDIDATE_STATE state;
    uint32_t priority;
    char id[ICE_CANDIDATE_ID_LEN + 1];
    KVS_SOCKET_PROTOCOL remoteProtocol;
} IceCandidate_t;

typedef struct {
    IceCandidate_t* local;
    IceCandidate_t* remote;
    uint32_t nominated;
    uint64_t priority;
    ICE_CANDIDATE_PAIR_STATE state;
    uint8_t connectivityChecks; // checking for completion of 4-way handshake
} IceCandidatePair_t;

typedef struct {
    IceCandidate_t* localCandidates[ KVS_ICE_MAX_LOCAL_CANDIDATE_COUNT ];
    IceCandidate_t* remoteCandidates[ KVS_ICE_MAX_REMOTE_CANDIDATE_COUNT ];
    IceServer_t* iceServers[ MAX_ICE_SERVERS_COUNT ];
    uint32_t iceServersCount;
    IceCandidatePair_t* iceCandidatePairs[ KVS_ICE_MAX_CANDIDATE_PAIR_COUNT ];
    uint32_t isControlling;
    uint64_t tieBreaker;
    // store transaction ids for stun binding request.
    TransactionIdStore_t* pStunBindingRequestTransactionIdStore;
} IceAgent_t;



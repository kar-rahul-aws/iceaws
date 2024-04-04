#ifndef ICE_AGENT_APIS_H
#define ICE_AGENT_APIS_H

/* Standard includes. */
#include <stdint.h>
#include <stddef.h>

#define ICE_CANDIDATE_ID_LEN                                    8
#define ICE_CONNECTIVITY_SUCCESS_FLAG                           15

#define DEFAULT_MAX_STORED_TRANSACTION_ID_COUNT                 20
#define MAX_STORED_TRANSACTION_ID_COUNT                         100

#define KVS_ICE_MAX_LOCAL_CANDIDATE_COUNT                       100
#define KVS_ICE_MAX_REMOTE_CANDIDATE_COUNT                      100
#define KVS_ICE_MAX_CANDIDATE_PAIR_COUNT                        1024
#define MAX_ICE_SERVERS_COUNT                                   21

/* ICE candidate priorities */
#define ICE_PRIORITY_HOST_CANDIDATE_TYPE_PREFERENCE             126
#define ICE_PRIORITY_SERVER_REFLEXIVE_CANDIDATE_TYPE_PREFERENCE 100
#define ICE_PRIORITY_PEER_REFLEXIVE_CANDIDATE_TYPE_PREFERENCE   110
#define ICE_PRIORITY_RELAYED_CANDIDATE_TYPE_PREFERENCE          0
#define ICE_PRIORITY_LOCAL_PREFERENCE                           65535

/**
 * Maximum allowed ICE configuration user name length
 * https://docs.aws.amazon.com/kinesisvideostreams/latest/dg/API_AWSAcuitySignalingService_GetIceServerConfig.html#API_AWSAcuitySignalingService_GetIceServerConfig_RequestSyntax
 */
#define MAX_ICE_CONFIG_USER_NAME_LEN                            256

/**
 * Maximum allowed ICE configuration password length
 * https://docs.aws.amazon.com/kinesisvideostreams/latest/dg/API_AWSAcuitySignalingService_IceServer.html#KinesisVideo-Type-AWSAcuitySignalingService_IceServer-Password
 */
#define MAX_ICE_CONFIG_CREDENTIAL_LEN                           256

/**
 * Maximum allowed ICE URI length
 */
#define MAX_ICE_CONFIG_URI_LEN                                  256


#define IS_IPV4_ADDR(pAddress)          ((pAddress)->family == KVS_IP_FAMILY_TYPE_IPV4)
// Byte sizes of the IP addresses
#define IPV6_ADDRESS_LENGTH                                     (uint16_t) 16
#define IPV4_ADDRESS_LENGTH                                     (uint16_t) 4

typedef enum {
    KVS_IP_FAMILY_TYPE_IPV4 = (uint16_t) 0x0001,
    KVS_IP_FAMILY_TYPE_IPV6 = (uint16_t) 0x0002,
} KVS_IP_FAMILY_TYPE;

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
    ICE_CANDIDATE_PAIR_STATE_VALID = 2,
    ICE_CANDIDATE_PAIR_STATE_NOMINATED = 3,
    ICE_CANDIDATE_PAIR_STATE_SUCCEEDED = 4
} IceCandidatePairState_t;

typedef enum {
    ICE_SOCKET_PROTOCOL_NONE,
    ICE_SOCKET_PROTOCOL_TCP,
    ICE_SOCKET_PROTOCOL_UDP,
} IceSocketProtocol_t;

typedef enum IceResult
{
    ICE_RESULT_OK,
    ICE_RESULT_START_NOMINATION,
    ICE_RESULT_UPDATE_SRFLX_CANDIDATE,
    ICE_RESULT_USE_CANDIDATE_FLAG,
    ICE_RESULT_SEND_STUN_LOCAL_REMOTE,
    ICE_RESULT_SEND_STUN_REMOTE_LOCAL,
    ICE_RESULT_SEND_STUN_REQUEST_RESPONSE,
    ICE_RESULT_CANDIDATE_PAIR_READY,
    ICE_RESULT_BASE = 0x53000000,
    ICE_RESULT_BAD_PARAM,
    ICE_RESULT_MAX_CANDIDATE_THRESHOLD,
    ICE_RESULT_MAX_CANDIDATE_PAIR_THRESHOLD,
    ICE_RESULT_OUT_OF_MEMORY,
    ICE_RESULT_SPRINT_ERROR
} IceResult_t;

/* ICE component structures */

typedef struct IPAddress
{
    uint16_t family;
    uint16_t port;
    uint8_t address[16];
} IPAddress_t;

typedef struct IceIPAddress
{
    IPAddress_t ipAddress;
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
    uint64_t priority;
    IceCandidatePairState_t state;
    uint8_t connectivityChecks; // checking for completion of 4-way handshake
} IceCandidatePair_t;

typedef struct IceAgent
{
    char localUsername[MAX_ICE_CONFIG_USER_NAME_LEN + 1];
    char localPassword[MAX_ICE_CONFIG_CREDENTIAL_LEN + 1];
    char remoteUsername[MAX_ICE_CONFIG_USER_NAME_LEN + 1];
    char remotePassword[MAX_ICE_CONFIG_CREDENTIAL_LEN + 1];
    char combinedUserName[(MAX_ICE_CONFIG_USER_NAME_LEN + 1) << 1];

    IceCandidate_t* localCandidates[ KVS_ICE_MAX_LOCAL_CANDIDATE_COUNT ];
    IceCandidate_t* remoteCandidates[ KVS_ICE_MAX_REMOTE_CANDIDATE_COUNT ];
    IceCandidatePair_t* iceCandidatePairs[ KVS_ICE_MAX_CANDIDATE_PAIR_COUNT ];
    uint32_t isControlling;
    uint64_t tieBreaker;
    TransactionIdStore_t* pStunBindingRequestTransactionIdStore;
} IceAgent_t;



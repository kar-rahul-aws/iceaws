#include "IceAgentAPIs.h"
#include <stdlib.h>
#include <stdbool.h>

/* Ice_AddHostCandidate - The application calls this API for adding host candidate. */
IceResult_t Ice_AddHostCandidate( IceCandidate_t * pCandidate, const IceIPAddress_t ipAddr, IceAgent_t * pIceAgent )
{
    IceResult_t retStatus = ICE_RESULT_OK;

    if( pCandidate == NULL )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }
    
    if( retStatus == ICE_RESULT_OK )
    {
        pCandidate->isRemote = 0;
        pCandidate->ipAddress = ipAddr;
        pCandidate->iceCandidateType = ICE_CANDIDATE_TYPE_HOST;
        pCandidate->state = ICE_CANDIDATE_STATE_VALID;
        pCandidate->priority = Ice_computeCandidatePriority(pCandidate);

        retStatus = Ice_InsertLocalCandidate(pIceAgent->localCandidates, (uint64_t) pCandidate );
    }

    return retStatus;
}

/* Ice_AddSrflxCandidate - The application calls this API for adding Server Reflex candidates. */

IceResult_t Ice_AddSrflxCandidate( IceCandidate_t * pCandidate, const IceIPAddress_t ipAddr, IceAgent_t * pIceAgent, IceServer_t *pIceServer, PStunPacket pStunPacket )
{
    IceResult_t retStatus = ICE_RESULT_OK;

    if( pCandidate == NULL || pStunPacket == NULL )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }
    
    if( retStatus == ICE_RESULT_OK )
    {
        pCandidate->isRemote = 0;
        pCandidate->ipAddress = ipAddr;
        pCandidate->iceCandidateType = ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE;
        pCandidate->state = ICE_CANDIDATE_STATE_NEW;
        pCandidate->priority = Ice_computeCandidatePriority(pCandidate);

        retStatus = Ice_createStunPacket( STUN_PACKET_TYPE_BINDING_REQUEST, &pStunPacket, pIceServer ); // we will define this function later

        if( retStatus == ICE_RESULT_OK )
        {
            retStatus = Ice_InsertLocalCandidate( pIceAgent->localCandidates, (uint64_t) pCandidate );
        }
    }
    return retStatus;
}

/* Ice_AddRemoteCandidate - The application calls this API for adding rempte candidates. */

IceResult_t Ice_AddRemoteCandidate( IceCandidate_t * pCandidate, IceAgent_t * pIceAgent, IceCandidatePair_t * pIceCandidatePair,
                                    IceCandidateType_t iceCandidateType, const IceIPAddress_t ipAddr, 
                                    IceSocketProtocol_t remoteProtocol, const uint32_t priority )
{
    IceResult_t retStatus = ICE_RESULT_OK;
    int i;

    if( pCandidate == NULL )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }
    
    if( Ice_GetValidRemoteCandidateCount( pIceAgent ) >= KVS_ICE_MAX_REMOTE_CANDIDATE_COUNT )
    {
        retStatus = ICE_RESULT_MAX_CANDIDATE_THRESHOLD;
    }

    if( retStatus == ICE_RESULT_OK ) 
    {
        pCandidate->isRemote = 1;
        pCandidate->ipAddress = ipAddr;
        pCandidate->state = ICE_CANDIDATE_STATE_VALID;
        pCandidate->priority = priority;
        pCandidate->iceCandidateType = iceCandidateType;
        pCandidate->remoteProtocol = remoteProtocol;

        retStatus = Ice_InsertRemoteCandidate( pIceAgent->remoteCandidates, (uint64_t) pCandidate );
    }
    
    if( retStatus == ICE_RESULT_OK )
    {
        for( i = 0; ( i < Ice_GetValidLocalCandidateCount( pIceAgent ) ) && ( retStatus == ICE_RESULT_OK ) ; i++ )
        {
            if( pIceAgent->localCandidates[ i ]->state == ICE_CANDIDATE_STATE_VALID )
            {
                retStatus = Ice_createCandidatePair( pIceAgent, pIceAgent->localCandidates[ i ], pCandidate, pIceCandidatePair );
            }
        }

    }

    return retStatus;
}

/*  Ice_createCandidatePair - The application calls this API for creating candidate pair between a local and remote candidate . */
IceResult_t Ice_createCandidatePair( IceAgent_t * pIceAgent, IceCandidate_t * pLocalCandidate, 
                                     IceCandidate_t * pRemoteCandidate, IceCandidatePair_t * pIceCandidatePair )
{
    IceResult_t retStatus = ICE_RESULT_OK;
    int iceCandidatePairCount;

    if( pIceAgent == NULL || pLocalCandidate == NULL || pRemoteCandidate == NULL || pIceCandidatePair == NULL)
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }

    if( retStatus == ICE_RESULT_OK )
    {
        iceCandidatePairCount = Ice_GetValidCandidatePairCount( pIceAgent );
        
        if( iceCandidatePairCount == KVS_ICE_MAX_CANDIDATE_PAIR_COUNT ){
            retStatus = ICE_RESULT_MAX_CANDIDATE_PAIR_THRESHOLD;
        }

        if( retStatus == ICE_RESULT_OK ){
            pIceCandidatePair->local = pLocalCandidate;
            pIceCandidatePair->remote = pRemoteCandidate;
            pIceCandidatePair->nominated = 0;
            pIceCandidatePair->state = ICE_CANDIDATE_PAIR_STATE_WAITING;
            pIceCandidatePair->priority = Ice_computeCandidatePairPriority(pIceCandidatePair, pIceAgent->isControlling);
        }

        Ice_insertCandidatePair( pIceAgent, pIceCandidatePair, iceCandidatePairCount );
    }

    return retStatus;
}

/* Ice_insertCandidatePair : This API is called internally to insert candidate paits based on decreasing priority. */
void Ice_insertCandidatePair( IceAgent_t * pIceAgent, IceCandidatePair_t * pIceCandidatePair, int iceCandidatePairCount )
{
    int i,pivot;
    
    for(i = 0; i < iceCandidatePairCount; i++ ){
        if( pIceCandidatePair->priority >=  pIceAgent->iceCandidatePairs[i]->priority ){
            pivot = i;
            break;
        }
    }
    
    for( i = iceCandidatePairCount; i > pivot; i-- ){
        pIceAgent->iceCandidatePairs[ i ] = pIceAgent->iceCandidatePairs[ i - 1 ];
    }
    
    pIceAgent->iceCandidatePairs[pivot] = pIceCandidatePair;
    
    return ;
}

/* Ice_updateSrflxCandidateAddress : This API will be called by processStunPacket, if the binding request is for finding srflx candidate to update the candidate address */
IceResult_t Ice_updateSrflxCandidateAddress( IceCandidate_t * pCandidate, const IceIPAddress_t * ipAddr, IceCandidatePair_t * pIceCandidatePair )
{
    IceResult_t retStatus = ICE_RESULT_OK;
    int i;

    if( pCandidate == NULL || ipAddr == NULL || pIceCandidate->iceCandidateType != ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }

    pIceCandidate->ipAddress = *pIpAddr;
    pIceCandidate->state = ICE_CANDIDATE_STATE_VALID;

    for( i = 0; ( i < Ice_GetValidRemoteCandidateCount( pIceAgent ) ) && ( retStatus == ICE_RESULT_OK ) ; i++ )
    {
        retStatus = Ice_createCandidatePair( pIceAgent, pCandidate, pIceAgent->remoteCandidates[ i ], pIceCandidatePair );
    }
    
    return retStatus;
}

/* Ice_InsertLocalCandidate - Adds a candidate into the array of local candidates */
IceResult_t Ice_InsertLocalCandidate( IceAgent_t * pIceAgent, IceCandidate_t * pCandidate )
{
    int i;
    IceResult_t retStatus = ICE_RESULT_OK;

    retStatus = ( Ice_GetValidLocalCandidateCount( pIceAgent ) == KVS_ICE_MAX_LOCAL_CANDIDATE_COUNT )? ICE_RESULT_MAX_CANDIDATE_THRESHOLD : ICE_RESULT_OK;

    if( retStatus == ICE_RESULT_OK )
    {
        for( i = 0; i < KVS_ICE_MAX_LOCAL_CANDIDATE_COUNT; i++ ){
            if( pIceAgent->localCandidates[ i ] == NULL ){
                pIceAgent->localCandidates[ i ] = pCandidate;
                break;
            }
        }
    }

    return retStatus;
}

/* Ice_InsertRemoteCandidate - Adds a candidate into the array of remote candidates */
IceResult_t Ice_InsertRemoteCandidate( IceAgent_t * pIceAgent, IceCandidate_t * pCandidate )
{
    int i;
    IceResult_t retStatus = ICE_RESULT_OK;

    retStatus = ( Ice_GetValidRemoteCandidateCount( pIceAgent ) == KVS_ICE_MAX_REMOTE_CANDIDATE_COUNT )? ICE_RESULT_MAX_CANDIDATE_THRESHOLD : ICE_RESULT_OK;

    if( retStatus == ICE_RESULT_OK )
    {
        for( i = 0; i < KVS_ICE_MAX_REMOTE_CANDIDATE_COUNT; i++ ){
            if( pIceAgent->remoteCandidates[ i ] == NULL ){
                pIceAgent->remoteCandidates[ i ] = pCandidate;
                break;
            }
        }
    }

    return retStatus;
}

/* Ice_GetValidLocalCandidateCount - Get valid Local Candidate count */
int Ice_GetValidLocalCandidateCount( IceAgent_t * pIceAgent )
{
    int i;

    for(i = 0; i < KVS_ICE_MAX_LOCAL_CANDIDATE_COUNT; i++ )
    {
        if( pIceAgent->localCandidates[ i ] == NULL ){
            break;
        }
    }
    return ( i + 1 );
}

/* Ice_GetValidRemoteCandidateCount - Get valid Remote Candidate count */
int Ice_GetValidRemoteCandidateCount( IceAgent_t * pIceAgent )
{
    int i;

    for(i = 0; i < KVS_ICE_MAX_REMOTE_CANDIDATE_COUNT; i++ )
    {
        if( pIceAgent->remoteCandidates[ i ] == NULL ){
            break;
        }
    }
    return ( i + 1 );
}

/* Ice_GetValidCandidatePairCount - Get valid Candidate Pair Count */
int Ice_GetValidCandidatePairCount( IceAgent_t * pIceAgent )
{
    int i;

    for(i = 0; i < KVS_ICE_MAX_CANDIDATE_PAIR_COUNT; i++ )
    {
        if( pIceAgent->iceCandidatePairs[ i ] == NULL ){
            break;
        }
    }
    return ( i + 1 );
}

/* Ice_computeCandidatePriority - Compute the candidate priority */
uint32_t Ice_computeCandidatePriority( IceCandidate_t * pIceCandidate )
{
    uint32_t typePreference = 0, localPreference = 0;
    
    switch ( pIceCandidate->iceCandidateType ) {
        case ICE_CANDIDATE_TYPE_HOST:
            typePreference = ICE_PRIORITY_HOST_CANDIDATE_TYPE_PREFERENCE;
            break;
        case ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE:
            typePreference = ICE_PRIORITY_SERVER_REFLEXIVE_CANDIDATE_TYPE_PREFERENCE;
            break;
        case ICE_CANDIDATE_TYPE_PEER_REFLEXIVE:
            typePreference = ICE_PRIORITY_PEER_REFLEXIVE_CANDIDATE_TYPE_PREFERENCE;
            break;
        case ICE_CANDIDATE_TYPE_RELAYED:
            typePreference = ICE_PRIORITY_RELAYED_CANDIDATE_TYPE_PREFERENCE;
            break;
    }

    if(!pIceCandidate->ipAddress.isPointToPoint) {
        localPreference = ICE_PRIORITY_LOCAL_PREFERENCE;
    }

    return ( (1 << 24) * (typePreference) + (1 << 8) * (localPreference) + 255 );
}

/* Ice_computeCandidatePairPriority - Compute the candidate pair priority */
uint64_t Ice_computeCandidatePairPriority( IceCandidatePair_t * pIceCandidatePair, uint32_t isLocalControlling )
{
    uint64_t controllingAgentCandidatePri = pIceCandidatePair->local->priority;
    uint64_t controlledAgentCandidatePri = pIceCandidatePair->remote->priority;

    if (!isLocalControlling) {
        controllingAgentCandidatePri = controlledAgentCandidatePri;
        controlledAgentCandidatePri = pIceCandidatePair->local->priority;
    }

    return ( ((uint64_t) 1 << 32) * MIN(controlledAgentCandidatePri, controllingAgentCandidatePri) +
        2 * MAX(controlledAgentCandidatePri, controllingAgentCandidatePri) + (controllingAgentCandidatePri > controlledAgentCandidatePri ? 1 : 0) );
}

#include "IceAgentAPIs.h"
#include <stdlib.h>
#include <stdbool.h>

/* Ice_AddHostCandidate - The application calls this API for adding host candidate. */

IceResult_t Ice_AddHostCandidate( PIceCandidate pCandidate, KvsIpAddress ipAddr, PIceAgent pIceAgent )
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
        pCandidate->foundation = pIceAgent->foundationCounter++;
        pCandidate->priority = Ice_computeCandidatePriority(pCandidate);

        retStatus = Ice_AddCandidate(pIceAgent->localCandidates, (uint64_t) pCandidate, 1 );
    }

    return retStatus;
}

/* Ice_AddSrflxCandidate - The application calls this API for adding Server Reflex candidates */

IceResult_t Ice_AddSrflxCandidate( PIceCandidate pCandidate, KvsIpAddress ipAddr, PIceAgent pIceAgent, uint32_t iceServerIndex, PStunPacket pStunPacket )
{
    IceResult_t retStatus = ICE_RESULT_OK;
    PIceServer pIceServer = pIceAgent->iceServers[iceServerIndex];

    if( pCandidate == NULL )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }
    
    if( retStatus == ICE_RESULT_OK )
    {
        pCandidate->isRemote = 0;
        pCandidate->ipAddress = ipAddr;
        pCandidate->iceCandidateType = ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE;
        pCandidate->state = ICE_CANDIDATE_STATE_NEW;
        pCandidate->iceServerIndex = iceServerIndex;
        pCandidate->foundation = pIceAgent->foundationCounter++;
        pCandidate->priority = Ice_computeCandidatePriority(pCandidate);

        retStatus = Ice_createStunPacket( (uint16_t)0x0001, &pStunPacket, 1 );

        if( retStatus == ICE_RESULT_OK )
        {
            retStatus = Ice_AddCandidate(pIceAgent->localCandidates, (uint64_t) pCandidate, 1 );
        }
    }
    return retStatus;
}

/* Ice_AddRemoteCandidate - The application calls this API for adding rempte candidates. */

IceResult_t Ice_AddRemoteCandidate( PIceCandidate pCandidate, PIceAgent pIceAgent, PIceCandidatePair pIceCandidatePair,
                                    ICE_CANDIDATE_TYPE iceCandidateType, KvsIpAddress ipAddr, 
                                    KVS_SOCKET_PROTOCOL remoteProtocol, uint32_t priority )
{
    IceResult_t retStatus = ICE_RESULT_OK;

    if( pCandidate == NULL )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }
    
    if( Ice_GetValidRemoteCandidateCount( pIceAgent ) >= KVS_ICE_MAX_REMOTE_CANDIDATE_COUNT )
    {
        retStatus = ICE_RESULT_MAX_CANDIDATE_THRESHOLD;
    }

    if( retStatus == ICE_RESULT_OK ) {
        pCandidate->isRemote = 1;
        pCandidate->ipAddress = ipAddr;
        pCandidate->state = ICE_CANDIDATE_STATE_VALID;
        pCandidate->priority = priority;
        pCandidate->iceCandidateType = iceCandidateType;
        pCandidate->remoteProtocol = remoteProtocol;
        
        retStatus = Ice_AddCandidate(pIceAgent->remoteCandidates, (uint64_t) pCandidate, 0 );
    }

    return retStatus;
}

/*  Ice_createCandidatePair - The application calls this API for creating candidate pair between a local and remote candidate . */
IceResult_t Ice_createCandidatePair( PIceAgent pIceAgent, PIceCandidate pLocalCandidate, PIceCandidate pRemoteCandidate, PIceCandidatePair pIceCandidatePair )
{
    IceResult_t retStatus = ICE_RESULT_OK;
    int iceCandidatePairCount;

    if( pIceAgent == NULL || pLocalCandidate == NULL || pRemoteCandidate == NULL || pIceCandidatePair == NULL){
        retStatus = ICE_RESULT_BAD_PARAM;
    }

    if( retStatus == ICE_RESULT_OK ){
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
static void Ice_insertCandidatePair( PIceAgent pIceAgent, PIceCandidatePair pIceCandidatePair, int iceCandidatePairCount )
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

/* Ice_createStunPacket - Create STUN request */
IceResult_t Ice_createStunPacket( PStunPacket pStunPacket, uint8_t* transactionId, uint32_t isBindingRequest )
{
    IceResult_t retStatus = ICE_RESULT_OK;

    uint32_t i;

    if( pStunPacket == NULL )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }

    if( retStatus == ICE_RESULT_OK ){
        pStunPacket->attributesCount = 0;
        pStunPacket->header.messageLength = 0;
        pStunPacket->header.magicCookie = ( (uint32_t) 0x2112A442 );
        pStunPacket->header.stunMessageType =  isBindingRequest ?  ( (uint16_t) 0x0001 ) : ( (uint16_t) 0x0101 ) ;

        if( transactionId == NULL ){
            for( i = 0;i < 12; i++ ) {
                pStunPacket->header.transactionId[i] = ( uint8_t )( rand() % 0xFF );
            }
        }
        else{
            for( i = 0;i < 12; i++ ) {
                pStunPacket->header.transactionId[i] = transactionId[ i ];
            }
        }
        
        pStunPacket->attributeList = (PStunAttributeHeader*) (pStunPacket + 1);
        
        pStunPacket->allocationSize = 2048;
    }
    // we need to serialize the packet as well
    // serializeStunPacket

    return retStatus;
}

/* Ice_ParseStunPacket - Parse STUN respose */
/* check if ID part works and IP address is necessary */
IceResult_t Ice_ParseStunPacket( PStunPacket pReceivedStunPacket, uint16_t messageType, PStunPacket pStunRequest, PStunPacket pStunResponse )
{
    IceResult_t retStatus = ICE_RESULT_OK;
    //messageType -> get the rhe raw pkt and update it

    switch( messageType ) {
        /* received a binding request from remote to local candidate 
         * create a Stun response from remote to local --> call Ice_CreateStunPacket
         * create a Stun request from local to remote --> call Ice_CreateStunPacket
         */
        case STUN_PACKET_TYPE_BINDING_REQUEST:
            if( pReceivedStunPacket == NULL || pStunRequest == NULL || pStunResponse == NULL ){
                retStatus = ICE_RESULT_BAD_PARAM;
            }
            if( retStatus == ICE_RESULT_OK ){
                //deserializeStunPacket
                retStatus = Ice_CreateStunPacket( pStunResponse, pReceivedStunPacket->header.transactionId, 0 );
                //append attributes
                
                retStatus = Ice_CreateStunPacket( pStunRequest, NULL, 1 );
                
                /* How to set Nominating flag for a candidate pair? 
                 * Application should tell us, which remote and local candidate the packet came to for this to be checked
                 * 1 option is , the application knows the srcIPAddr ( of remote candidate ) 
                 * and the destIPAddr ( of local candidate ). Using these addresses, add an API 
                 * to find the local candidate and remote candidate, and then find the corresponding 
                 * candidate pair. Once the STUN packets are created, we can set the nominated flag 
                 * as TRUE for this particular candidate pair.
                 */
            }
            
        /* received a response from remote to local candidate */
        case STUN_PACKET_TYPE_BINDING_RESPONSE_SUCCESS:
            /* No STUN packet is needed to be sent, on receiving a response back from the remote
             * candidates. We can start the nomination process, with an API on every Binding response
             * received. Nomination process -> go through the candidate pairs, check the nominated flag 
             * create a STUN request using the Ice_CreateStunPacket API for last connectivity check ( if agent is controlling )
             * set it to Ready state ( ? )
             */
        default:
            break;
    }
}

/* Ice_FindLocalCandidateFromIPAddr - The library calls this API internally to find local candidate from a given IP address */
PIceCandidate Ice_FindLocalCandidateFromIPAddr( PIceAgent pIceAgent, KvsIpAddress ipAddr ){
    PIceCandidate pLocalCandidate = NULL;

    int i;

    for( i = 0; i < Ice_GetValidLocalCandidateCount( pIceAgent ); i++ ){
        if( Ice_compareIPAddr( pIceAgent->localCandidates[i]->ipAddress, ipAddr ) )
        {
            pLocalCandidate = pIceAgent->localCandidates[i];
            break;
        }
    }

    return pLocalCandidate;
}

/* Ice_FindRemoteCandidateFromIPAddr - The library calls this API internally to find remote candidate from a given IP address */
PIceCandidate Ice_FindRemoteCandidateFromIPAddr( PIceAgent pIceAgent, KvsIpAddress ipAddr ){
    PIceCandidate pRemoteCandidate = NULL;

    int i;

    for( i = 0; i < Ice_GetValidRemoteCandidateCount( pIceAgent ); i++ ){
        if( Ice_compareIPAddr( pIceAgent->remoteCandidates[i]->ipAddress, ipAddr ) )
        {
            pRemoteCandidate = pIceAgent->remoteCandidates[i];
            break;
        }
    }

    return pRemoteCandidate;
}

/* Ice_FindCandidatePair - The library calls this API internally to find candidate pair from a given IP address */
PIceCandidatePair Ice_FindCandidatePair( PIceAgent pIceAgent, KvsIpAddress localIP, KvsIpAddress remoteIP ){
    PIceCandidatePair pCandidatePair = NULL;
    
    int i;
    
    for( i = 0; i < Ice_GetValidCandidatePairCount( pIceAgent ); i++ ){
        if( Ice_compareIPAddr( pIceAgent->iceCandidatePairs[i]->local->ipAddress, pIceAgent->iceCandidatePairs[i]->remote->ipAddress ) ){
            pCandidatePair = pIceAgent->iceCandidatePairs[i];
            break;
        }
    }
    
    return pCandidatePair;
}

/* Ice_compareIPAddr - The library calls this API internally to compare 2 IP addresses */
static bool Ice_compareIPAddr( KvsIpAddress ipAddr1 , KvsIpAddress ipAddr2 ){

    bool result = false;

    if( ( ipAddr1.family == ipAddr2.family ) && ( ipAddr1.port == ipAddr2.port ) && ( ipAddr1.address == ipAddr2.address ) ){
        result = true;
    }

    return result;
}

/* Ice_AddCandidate - Adds a candidate into the array of candidates */
static IceResult_t Ice_AddCandidate( PIceAgent pIceAgent, PIceCandidate pCandidate, uint32_t isLocal )
{
    int i;
    IceResult_t retStatus = ICE_RESULT_OK;

    if( isLocal ){
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
    }
    else{
        retStatus = ( Ice_GetValidRemoteCandidateCount( pIceAgent ) == KVS_ICE_MAX_LOCAL_CANDIDATE_COUNT )? ICE_RESULT_MAX_CANDIDATE_THRESHOLD : ICE_RESULT_OK;

        if( retStatus == ICE_RESULT_OK )
        {
            for( i = 0; i < KVS_ICE_MAX_REMOTE_CANDIDATE_COUNT; i++ ){
                if( pIceAgent->remoteCandidates[ i ] == NULL ){
                    pIceAgent->remoteCandidates[ i ] = pCandidate;
                    retStatus = 1;
                    break;
                }
            }
        }
    }
    return retStatus;
}

/* Ice_GetValidLocalCandidateCount - Get valid Local Candidate count */
static int Ice_GetValidLocalCandidateCount( PIceAgent pIceAgent )
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
static int Ice_GetValidRemoteCandidateCount( PIceAgent pIceAgent )
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
static int Ice_GetValidCandidatePairCount( PIceAgent pIceAgent )
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
static uint32_t Ice_computeCandidatePriority( PIceCandidate pIceCandidate )
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
static uint64_t Ice_computeCandidatePairPriority( PIceCandidatePair pIceCandidatePair, uint32_t isLocalControlling )
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

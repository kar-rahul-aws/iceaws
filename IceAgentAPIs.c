#include "IceAgentAPIs.h"
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

/* Ice_createIceAgent - The application calls this API for starting a new ICE agent. */

IceResult_t Ice_createIceAgent( IceAgent_t * pIceAgent, char * localUsername, 
                                char * localPassword, char * remoteUsername, 
                                char * remotePassword, TransactionIdStore_t * pBuffer )
{
    IceResult_t retStatus = ICE_RESULT_OK;

    if( pIceAgent == NULL || localPassword == NULL || localUsername == NULL || remotePassword == NULL || remoteUsername == NULL || pBuffer == NULL )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }

    strcpy( pIceAgent->localUsername, localUsername );
    strcpy( pIceAgent->localPassword, localPassword );
    strcpy( pIceAgent->remoteUsername, remoteUsername );
    strcpy( pIceAgent->remotePassword, remotePassword );

    pIceAgent->isControlling = 0;
    pIceAgent->tieBreaker = ( uint64_t ) rand(); //required as an attribute for STUN packet
    
    pIceAgent->pStunBindingRequestTransactionIdStore = pBuffer;
    retStatus = Ice_createTransactionIdStore(DEFAULT_MAX_STORED_TRANSACTION_ID_COUNT, &pIceAgent->pStunBindingRequestTransactionIdStore);

    return retStatus;
}

/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_AddHostCandidate - The application calls this API for adding host candidate. */

IceResult_t Ice_AddHostCandidate( const IceIPAddress_t ipAddr, IceAgent_t * pIceAgent )
{
    IceResult_t retStatus = ICE_RESULT_OK;
    IceCandidate_t * pCandidate = NULL;
    int localCandidateCount = Ice_GetValidLocalCandidateCount( pIceAgent );
    
    if( localCandidateCount == KVS_ICE_MAX_LOCAL_CANDIDATE_COUNT )
    {
        retStatus = ICE_RESULT_MAX_CANDIDATE_THRESHOLD;
    }
    else
    {
        pCandidate = pIceAgent->localCandidates[ localCandidateCount ];
    }
    
    if( retStatus == ICE_RESULT_OK )
    {
        pCandidate->isRemote = 0;
        pCandidate->ipAddress = ipAddr;
        pCandidate->iceCandidateType = ICE_CANDIDATE_TYPE_HOST;
        pCandidate->state = ICE_CANDIDATE_STATE_VALID;
        pCandidate->priority = Ice_computeCandidatePriority(pCandidate);

        retStatus = Ice_InsertLocalCandidate(pIceAgent->localCandidates, pCandidate );
    }

    return retStatus;
}

/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_AddSrflxCandidate - The application calls this API for adding Server Reflex candidate. */

IceResult_t Ice_AddSrflxCandidate( const IceIPAddress_t ipAddr, IceAgent_t * pIceAgent, IceServer_t * pIceServer,
                                   StunContext_t * pStunCxt, uint8_t * pStunMessageBuffer, StunHeader_t * pStunHeader )
{
    IceResult_t retStatus = ICE_RESULT_OK;
    IceCandidate_t * pCandidate = NULL;

    int localCandidateCount = Ice_GetValidLocalCandidateCount( pIceAgent );

    if( localCandidateCount == KVS_ICE_MAX_LOCAL_CANDIDATE_COUNT )
    {
        retStatus = ICE_RESULT_MAX_CANDIDATE_THRESHOLD;
    }
    else
    {
        pCandidate = pIceAgent->localCandidates[ localCandidateCount ];
    }

    if( retStatus == ICE_RESULT_OK )
    {
        pCandidate->isRemote = 0;
        pCandidate->ipAddress = ipAddr;
        pCandidate->iceCandidateType = ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE;
        pCandidate->state = ICE_CANDIDATE_STATE_NEW;
        pCandidate->priority = Ice_computeCandidatePriority(pCandidate);

        retStatus = Ice_createRequestForSrflxCandidate( pIceAgent, pStunCxt, pStunMessageBuffer, pStunHeader );

        if( retStatus == ICE_RESULT_OK )
        {
            retStatus = Ice_InsertLocalCandidate( pIceAgent->localCandidates, pCandidate );
        }

    }
    return retStatus;
}

/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_AddRemoteCandidate - The application calls this API for adding remote candidates. */

IceResult_t Ice_AddRemoteCandidate( IceAgent_t * pIceAgent, IceCandidateType_t iceCandidateType, 
                                    const IceIPAddress_t ipAddr, IceSocketProtocol_t remoteProtocol, 
                                    const uint32_t priority )
{
    IceResult_t retStatus = ICE_RESULT_OK;
    IceCandidate_t * pCandidate = NULL;
    int i;

    int remoteCandidateCount = Ice_GetValidRemoteCandidateCount( pIceAgent );

    if( remoteCandidateCount == KVS_ICE_MAX_LOCAL_CANDIDATE_COUNT )
    {
        retStatus = ICE_RESULT_MAX_CANDIDATE_THRESHOLD;
    }
    else
    {
        pCandidate = pIceAgent->remoteCandidates[ remoteCandidateCount ];
    }

    if( retStatus == ICE_RESULT_OK ) 
    {
        pCandidate->isRemote = 1;
        pCandidate->ipAddress = ipAddr;
        pCandidate->state = ICE_CANDIDATE_STATE_VALID;
        pCandidate->priority = priority;
        pCandidate->iceCandidateType = iceCandidateType;
        pCandidate->remoteProtocol = remoteProtocol;

        retStatus = Ice_InsertRemoteCandidate( pIceAgent->remoteCandidates, pCandidate );
    }
    
    if( retStatus == ICE_RESULT_OK )
    {
        for( i = 0; ( i < Ice_GetValidLocalCandidateCount( pIceAgent ) ) && ( retStatus == ICE_RESULT_OK ) ; i++ )
        {
            if( pIceAgent->localCandidates[ i ]->state == ICE_CANDIDATE_STATE_VALID )
            {
                retStatus = Ice_createCandidatePair( pIceAgent, pIceAgent->localCandidates[ i ], pCandidate );
            }
        }

    }

    return retStatus;
}

/*------------------------------------------------------------------------------------------------------------------*/

/*  Ice_createCandidatePair - The library calls this API for creating candidate pair between a local and remote candidate . */

IceResult_t Ice_createCandidatePair( IceAgent_t * pIceAgent, IceCandidate_t * pLocalCandidate, 
                                     IceCandidate_t * pRemoteCandidate )
{
    IceResult_t retStatus = ICE_RESULT_OK;
    int iceCandidatePairCount;
    IceCandidatePair_t * pIceCandidatePair = NULL;

    if( pIceAgent == NULL || pLocalCandidate == NULL || pRemoteCandidate == NULL )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }

    if( retStatus == ICE_RESULT_OK )
    {
        iceCandidatePairCount = Ice_GetValidCandidatePairCount( pIceAgent );
        
        if( iceCandidatePairCount == KVS_ICE_MAX_CANDIDATE_PAIR_COUNT )
        {
            retStatus = ICE_RESULT_MAX_CANDIDATE_PAIR_THRESHOLD;
        }
        else
        {
            pIceCandidatePair = pIceAgent->iceCandidatePairs[ iceCandidatePairCount ];
        }

        if( retStatus == ICE_RESULT_OK ){
            pIceCandidatePair->local = pLocalCandidate;
            pIceCandidatePair->remote = pRemoteCandidate;
            pIceCandidatePair->state = ICE_CANDIDATE_PAIR_STATE_WAITING;
            pIceCandidatePair->priority = Ice_computeCandidatePairPriority(pIceCandidatePair, pIceAgent->isControlling);
            pIceCandidatePair->connectivityChecks = 0;
        }

        Ice_insertCandidatePair( pIceAgent, pIceCandidatePair, iceCandidatePairCount );
    }

    return retStatus;
}

/*------------------------------------------------------------------------------------------------------------------*/

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

/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_updateSrflxCandidateAddress : This API will be called by processStunPacket, if the binding request is for finding srflx candidate to update the candidate address */

IceResult_t Ice_updateSrflxCandidateAddress( IceAgent_t * pIceAgent,IceCandidate_t * pCandidate, const IceIPAddress_t * pIpAddr )
{
    IceResult_t retStatus = ICE_RESULT_OK;
    int i;

    if( pCandidate == NULL || pIpAddr == NULL || pCandidate->iceCandidateType != ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }

    pCandidate->ipAddress = *pIpAddr;
    pCandidate->state = ICE_CANDIDATE_STATE_VALID;

    for( i = 0; ( ( i < Ice_GetValidRemoteCandidateCount( pIceAgent ) ) && ( retStatus == ICE_RESULT_OK ) ) ; i++ )
    {
        retStatus = Ice_createCandidatePair( pIceAgent, pCandidate, pIceAgent->remoteCandidates[ i ] );
    }

    return retStatus;
}

/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_InitializeStunPacket - Populates the Stun packet, whose memory has been allocated by the application.
 *  4 types of packets need to be created:
 *   1. Send Srflx Request
 *   2. Connectivity Check
 *   3. During nomination - USE_CANDIDATE flag
 *   4. Send Response to Remote Candidates
 */
IceResult_t Ice_InitializeStunPacket( StunContext_t * pStunCxt, uint8_t * transactionId, 
                                      uint8_t * pStunMessageBuffer, StunHeader_t * pStunHeader,
                                      uint8_t isGenerateTransactionID, uint8_t isStunBindingRequest )
{
    IceResult_t retStatus = ICE_RESULT_OK;
    int i;

    if( pStunCxt == NULL || pStunHeader == NULL || pStunMessageBuffer == NULL )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }

    /* STUN header */
    if( isStunBindingRequest )
    {
        pStunHeader->messageType =  STUN_MESSAGE_TYPE_BINDING_REQUEST;
    }
    else
    {
        pStunHeader->messageType =  STUN_PACKET_TYPE_BINDING_RESPONSE_SUCCESS;
    }
    
    if( isGenerateTransactionID == 1 )
    {
        for( i = 0; i < STUN_HEADER_TRANSACTION_ID_LENGTH; i++ )
        {
            pStunHeader->transactionId[ i ] = ( uint8_t )( rand() % 0x100 );
        }
    }
    else if( transactionId == NULL )
    {
        for( i = 0; i < STUN_HEADER_TRANSACTION_ID_LENGTH; i++ )
        {
            pStunHeader->transactionId[ i ] = ( uint8_t )( rand() % 0xFF );
        }
    }
    else
    {
        memcpy( &( pStunHeader->transactionId[ 0 ] ), &( transactionId[ 0 ] ), STUN_HEADER_TRANSACTION_ID_LENGTH );
    }
    
    /* Create a STUN message. */
    retStatus = StunSerializer_Init(  pStunCxt ,
                                      pStunMessageBuffer,
                                      1024, //Keeping the static size = 1024 , for now, if required, it can be made dynamic as well.
                                      pStunHeader );

    return retStatus;
}

/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_packageStunPacket - This API takes care of the serialization of the Stun Packet and appends the requited attributes .*/

IceResult_t Ice_packageStunPacket( StunContext_t * pStunCxt, uint8_t * password, uint32_t passwordLen )
{
    IceResult_t retStatus = ICE_RESULT_OK;
    uint8_t * pIntBuffer;
    uint8_t messageIntegrity[STUN_HMAC_VALUE_LEN] , pFinBuffer;
    uint32_t hmacLen , crc32;
    uint16_t bufferLength , stunMessageLength;

    if( ( password == NULL && passwordLen > 0 ) || ( password != NULL && passwordLen == 0 ) )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }
    
    //Add Integrity attribute
    if( ( retStatus == ICE_RESULT_OK ) && ( password != NULL ) )
    {
        retStatus = StunSerializer_GetIntegrityBuffer( pStunCxt, &pIntBuffer, &bufferLength );
        //Application
        if( ( pIntBuffer != NULL ) && ( retStatus == ICE_RESULT_OK ) )
        {
            KVS_SHA1_HMAC(password, (int32_t) passwordLen, pIntBuffer, bufferLength, messageIntegrity, &hmacLen);
        }
        
        retStatus = StunSerializer_AddAttributeIntegrity(pStunCxt, messageIntegrity, STUN_HMAC_VALUE_LEN);
    }
    
    //Add Fingerprint attribute
    if( retStatus == ICE_RESULT_OK )
    {
        retStatus = StunSerializer_GetFingerprintBuffer( pStunCxt, &pFinBuffer, &bufferLength );

        //Application
        if(pFinBuffer != NULL)
        {
            crc32 = COMPUTE_CRC32(pFinBuffer, (uint32_t) bufferLength) ^ STUN_FINGERPRINT_ATTRIBUTE_XOR_VALUE;
        }
        retStatus = StunSerializer_AddAttributeFingerprint( pStunCxt, crc32 );
    }
    
    if( retStatus == ICE_RESULT_OK )
    {
        retStatus = StunSerializer_Finalize( pStunCxt, &( stunMessageLength ) );
    }
    
    return retStatus;
}

/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_createRequestForSrflxCandidate - This API creates Stun Packet for sending Srflx candidate request. */

IceResult_t Ice_createRequestForSrflxCandidate( IceAgent_t * pIceAgent, StunContext_t * pStunCxt, 
                                                uint8_t * pStunMessageBuffer, StunHeader_t * pStunHeader )
{
    IceResult_t retStatus = ICE_RESULT_OK;

    retStatus = Ice_InitializeStunPacket( pStunCxt, NULL, pStunMessageBuffer, pStunHeader, 1, 1 );
    
    Ice_transactionIdStoreInsert( pIceAgent->pStunBindingRequestTransactionIdStore, pStunHeader->transactionId );
    
    if( retStatus == ICE_RESULT_OK )
    {
        retStatus = Ice_packageStunPacket( pStunCxt, NULL, 0 );
    }

    return retStatus;
}

/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_createRequestForNominatingValidCandidate - This API creates Stun Packet for nomination of the valid candidate Pair. */

IceResult_t Ice_createRequestForNominatingValidCandidate( StunContext_t * pStunCxt, IceAgent_t * pIceAgent, 
                                                          uint8_t * pStunMessageBuffer, StunHeader_t * pStunHeader,
                                                          IceCandidatePair_t * pIceCandidatePair )
{
    IceResult_t retStatus = ICE_RESULT_OK;

    retStatus = Ice_InitializeStunPacket( pStunCxt, NULL, pStunMessageBuffer, pStunHeader, 0, 1 );
    
    if( retStatus == ICE_RESULT_OK )
    {
        retStatus = StunSerializer_AddAttributeUsername( pStunCxt, pIceAgent->combinedUserName, strlen( pIceAgent->combinedUserName ) );
        
        if( retStatus == ICE_RESULT_OK )
        {
            retStatus = StunSerializer_AddAttributePriority( pStunCxt, pIceCandidatePair->local->priority );
            
            if( retStatus == ICE_RESULT_OK )
            {
                retStatus = StunSerializer_AddAttributeIceControlling( pStunCxt, pIceAgent->tieBreaker );
                
                if( retStatus == ICE_RESULT_OK )
                {
                    retStatus = StunSerializer_AddAttributeUseCandidate( pStunCxt );
                }
            }
        }
    }

    
    if( retStatus == ICE_RESULT_OK )
    {
        retStatus = Ice_packageStunPacket( pStunCxt, ( uint8_t * ) pIceAgent->remotePassword, ( uint32_t ) strlen( pIceAgent->remotePassword ) * sizeof( char ) );
    }

    return retStatus;

}

/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_createRequestForConnectivityCheck - This API creates Stun Packet for connectivity check to the remote candidate . */

IceResult_t Ice_createRequestForConnectivityCheck( StunContext_t * pStunCxt, IceAgent_t * pIceAgent,
                                                   uint8_t * pStunMessageBuffer, StunHeader_t * pStunHeader )
{
    IceResult_t retStatus = ICE_RESULT_OK;

    retStatus = Ice_InitializeStunPacket( pStunCxt, NULL, pStunMessageBuffer, pStunHeader, 0, 1 );
        
    if( retStatus == ICE_RESULT_OK )
    {
        retStatus = StunSerializer_AddAttributeUsername( pStunCxt, pIceAgent->combinedUserName, strlen( pIceAgent->combinedUserName ) );

        if( retStatus == ICE_RESULT_OK )
        {
            retStatus = StunSerializer_AddAttributePriority( pStunCxt, 0 );
            
            if( retStatus == ICE_RESULT_OK )
            {
                if( !pIceAgent->isControlling )
                {
                    retStatus = StunSerializer_AddAttributeIceControlled( pStunCxt, pIceAgent->tieBreaker );
                }
                else
                {
                    retStatus = StunSerializer_AddAttributeIceControlling( pStunCxt, pIceAgent->tieBreaker );
                }
            }
        }
    }
    
    if( retStatus == ICE_RESULT_OK )
    {
        retStatus = Ice_packageStunPacket( pStunCxt, ( uint8_t * ) pIceAgent->remotePassword, ( uint32_t ) strlen( pIceAgent->remotePassword ) * sizeof( char ) );
    }

    return retStatus;

}

/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_createResponseForRequest - This API creates Stun Packet for response to a Stun Binding Request. */

IceResult_t Ice_createResponseForRequest( StunContext_t * pStunCxt, IceAgent_t * pIceAgent,
                                          uint8_t * pStunMessageBuffer, StunHeader_t * pStunHeader,
                                          IceIPAddress_t * pSrcAddr )
{
    IceResult_t retStatus = ICE_RESULT_OK;
    
    if( pIceAgent == NULL || pStunCxt == NULL || pStunMessageBuffer == NULL || pStunHeader == NULL )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }
    
    retStatus = Ice_InitializeStunPacket( pStunCxt, NULL, pStunMessageBuffer, pStunHeader, 0, 0 );
    
    if( retStatus == ICE_RESULT_OK )
    {
        retStatus = StunSerializer_AddAttributeXorMappedAddress( pStunCxt , pSrcAddr->ipAddress );
        
        if( retStatus == ICE_RESULT_OK )
        {
            if( !pIceAgent->isControlling )
            {
                retStatus = StunSerializer_AddAttributeIceControlled( pStunCxt, pIceAgent->tieBreaker );
            }
            else
            {
                retStatus = StunSerializer_AddAttributeIceControlling( pStunCxt, pIceAgent->tieBreaker );
            }
        }
        
        if( retStatus == ICE_RESULT_OK )
        {
            retStatus = Ice_packageStunPacket( pStunCxt, ( uint8_t * ) pIceAgent->localPassword, ( uint32_t ) strlen( pIceAgent->localPassword ) * sizeof( char ) );
        }
    }
    return retStatus;

}
/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_DeserializeStunPacket - This API deserializes a received STUN packet . */

IceResult_t Ice_DeserializeStunPacket( StunContext_t * pStunCxt, StunAttribute_t * pStunAttribute )
{
    IceResult_t retStatus = ICE_RESULT_OK;
    
    while( retStatus == ICE_RESULT_OK )
    {
        retStatus = StunDeserializer_GetNextAttribute( pStunCxt, pStunAttribute );
        
        if( retStatus == ICE_RESULT_OK )
        {
            switch( pStunAttribute->attributeType )
            {
                case STUN_ATTRIBUTE_TYPE_XOR_MAPPED_ADDRESS:
                {
                    retStatus |= ICE_RESULT_UPDATE_SRFLX_CANDIDATE;
                }
                break;
                case STUN_ATTRIBUTE_TYPE_USE_CANDIDATE:
                {
                    retStatus |= ICE_RESULT_USE_CANDIDATE_FLAG;
                }
                break;
                default:
                    break;
            }
        }
    }
    return retStatus;
}
/*------------------------------------------------------------------------------------------------------------------*/

/*
    +-----+-----+-----+-----+-----+
    |     | BIT3| BIT2| BIT1| BIT0|
    +-----+-----+-----+-----+-----+
    
    This depicts the connectivityChecks in a candidate pair, these 4 bits show which bit stands for which STUN request/ response.
    
     1. BIT0 - STUN request from local candidate to remote candidate.
     2. BIT1 - STUN response from remote candidate to local candidate.
     3. BIT2 - STUN request from remote candidate to local candidate.
     4. BIT3 - STUN response from local candidate to remote candidate.

*/

/* Ice_handleStunResponse - This API handles the processing of Stun Response. */

IceResult_t Ice_handleStunResponse( StunContext_t * pStunCxt , IceAgent_t * pIceAgent, StunAttribute_t * pStunAttribute,
                                    uint8_t * pStunMessageBuffer, uint8_t pStunMessageBufferLength, StunAttributeAddress_t * pStunAttributeAddress,
                                    IceCandidate_t * pLocalCandidate , IceIPAddress_t * pSrcAddr,
                                    StunHeader_t * pStunHeader, IceCandidatePair_t * pIceCandidatePair )
{
    IceResult_t retStatus = ICE_RESULT_OK;
    
    if( pIceAgent == NULL || pStunCxt == NULL || pStunMessageBuffer == NULL || pStunHeader == NULL )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }
    
    /* Initialize STUN context for deserializing. */
    retStatus = StunDeserializer_Init( pStunCxt, pStunMessageBuffer, pStunMessageBufferLength, pStunHeader );
    
    if( retStatus == ICE_RESULT_OK )
    {
        retStatus = Ice_DeserializeStunPacket( pStunCxt, pStunAttribute );
    }
    
    switch( pStunHeader->messageType )
    {
        case STUN_PACKET_TYPE_BINDING_REQUEST:
        
            /* Check if received candidate with USE_CANDIDATE FLAG */
            if( ( retStatus & ( 1 << ICE_RESULT_USE_CANDIDATE_FLAG ) && ( ( pIceCandidatePair->connectivityChecks ^ ICE_CONNECTIVITY_SUCCESS_FLAG ) == 0 ) ) )
            {
                printf( "received candidate with USE_CANDIDATE flag.\n" );
                pIceCandidatePair->state = ICE_CANDIDATE_PAIR_STATE_NOMINATED;
                retStatus = Ice_createResponseForRequest( pStunCxt, pIceAgent, pStunMessageBuffer, pStunHeader, pSrcAddr );
            }
            else
            {
                pIceCandidatePair->connectivityChecks |= 1<<2;

                /* Create a response from local to remote candidate. */
                retStatus = Ice_createResponseForRequest( pStunCxt, pIceAgent, pStunMessageBuffer, pStunHeader, pSrcAddr );
                if( retStatus == ICE_RESULT_OK )
                {
                    pIceCandidatePair->connectivityChecks |= 1<<3;
                    retStatus |= ICE_RESULT_SEND_STUN_LOCAL_REMOTE;
                }
                
                /* Check if we need to add Peer Reflexive candidates. */
                
                if( ( pIceCandidatePair->connectivityChecks & 1 ) == 0 )
                {
                    /* Create a request from local to remote candidate. */
                    pIceCandidatePair->connectivityChecks |= 1<<0;
                    
                    retStatus = Ice_createRequestForConnectivityCheck( pStunCxt, pIceAgent, pStunMessageBuffer, pStunHeader );
                    if( retStatus == ICE_RESULT_OK )
                    {
                        retStatus |= ICE_RESULT_SEND_STUN_REQUEST_RESPONSE;
                    }

                }
            }
        case STUN_PACKET_TYPE_BINDING_RESPONSE_SUCCESS:
        
            if( Ice_transactionIdStoreHasId( pIceAgent->pStunBindingRequestTransactionIdStore, pStunMessageBuffer + STUN_PACKET_TRANSACTION_ID_OFFSET ) )
            {
                retStatus = Ice_HandleServerReflexiveCandidateResponse( pIceAgent, pStunMessageBuffer, pStunMessageBufferLength, pStunHeader, pLocalCandidate );
                
                if( retStatus == ICE_RESULT_OK )
                {
                    Ice_transactionIdStoreRemove( pIceAgent->pStunBindingRequestTransactionIdStore, pStunMessageBuffer + STUN_PACKET_TRANSACTION_ID_OFFSET );
                }
            }
            else
            {
                pIceCandidatePair->connectivityChecks |= 1<<1;
                
                if( ( pIceCandidatePair->connectivityChecks ^ ICE_CONNECTIVITY_SUCCESS_FLAG ) == 0 )
                {
                    if( pIceCandidatePair->state == ICE_CANDIDATE_PAIR_STATE_NOMINATED )
                    {
                        pIceCandidatePair->state = ICE_CANDIDATE_PAIR_STATE_SUCCEEDED;
                        retStatus |= ICE_RESULT_CANDIDATE_PAIR_READY;
                    }
                    else
                    {
                        pIceCandidatePair->state = ICE_CANDIDATE_PAIR_STATE_VALID;
                        retStatus |= ICE_RESULT_START_NOMINATION;
                    }
                }
            }
            
            break;
        default:
            printf( "Stun packet received is neither a Binding Request nor a Response.\n");
            break;
    }
    return retStatus;
}

/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_HandleServerReflexiveCandidateResponse - 1. Parse STUN Binding Response from the STUN server to get Server Reflexive candidate.
                                                2. Add the Server Reflexive candidate to the ICE Library. */

IceResult_t Ice_HandleServerReflexiveCandidateResponse( IceAgent * pIceAgent, StunAttribute_t * pStunAttribute,
                                                        StunAttributeAddress_t * pStunMappedAddress, StunHeader_t * pStunHeader,
                                                        IceCandidate_t * pLocalCandidate )
{
    IceResult_t retStatus = ICE_RESULT_OK;
    IceIPAddress_t * ipAddr;

    retStatus = StunDeserializer_ParseAttributeXORMappedAddress( pStunAttribute, pStunMappedAddress, pStunHeader->transactionId );
    
    if( retStatus == ICE_RESULT_OK )
    {
        ipAddr->ipAddress = ( IPAddress_t * )( pStunMappedAddress->address );
        ipAddr->isPointToPoint = 0;

        retStatus = Ice_updateSrflxCandidateAddress( pIceAgent, pLocalCandidate, ipAddr );
    }

    return retStatus;
}
/*------------------------------------------------------------------------------------------------------------------*/



/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_InsertLocalCandidate - Adds a candidate into the array of local candidates. */

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

/*------------------------------------------------------------------------------------------------------------------*/

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

/*------------------------------------------------------------------------------------------------------------------*/

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

/*------------------------------------------------------------------------------------------------------------------*/

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

/*------------------------------------------------------------------------------------------------------------------*/

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

/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_computeCandidatePriority - Compute the candidate priority */

static uint32_t Ice_computeCandidatePriority( IceCandidate_t * pIceCandidate )
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

/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_computeCandidatePairPriority - Compute the candidate pair priority */

static uint64_t Ice_computeCandidatePairPriority( IceCandidatePair_t * pIceCandidatePair, uint32_t isLocalControlling )
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

/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_createTransactionIdStore - Creates the Transaction ID Store. */

static IceResult_t Ice_createTransactionIdStore(uint32_t maxIdCount, TransactionIdStore_t * pTransactionIdStore)
{
    IceResult_t retStatus = ICE_RESULT_OK;

    if( ( maxIdCount > MAX_STORED_TRANSACTION_ID_COUNT ) || ( maxIdCount < 0 ) )
    {
        retStatus = ICE_RESULT_BAD_PARAM;
    }

    if( retStatus == ICE_RESULT_OK )
    {
        pTransactionIdStore->transactionIds = ( uint8_t * )( pTransactionIdStore + 1 );
        pTransactionIdStore->maxTransactionIdsCount = maxIdCount;
    }

    return retStatus;
}

/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_transactionIdStoreInsert - Inserts the Transaction in the IceAgent Transaction ID Store. */

static void Ice_transactionIdStoreInsert(TransactionIdStore_t * pTransactionIdStore, uint8_t * transactionId)
{
    uint8_t * storeLocation = NULL;
    uint32_t transactionIDCount ;

    CHECK(pTransactionIdStore != NULL);

    storeLocation = pTransactionIdStore->transactionIds +
        ((pTransactionIdStore->nextTransactionIdIndex % pTransactionIdStore->maxTransactionIdsCount) * STUN_TRANSACTION_ID_LEN);
    MEMCPY(storeLocation, transactionId, STUN_TRANSACTION_ID_LEN);

    pTransactionIdStore->nextTransactionIdIndex = (pTransactionIdStore->nextTransactionIdIndex + 1) % pTransactionIdStore->maxTransactionIdsCount;

    if (pTransactionIdStore->nextTransactionIdIndex == pTransactionIdStore->earliestTransactionIdIndex) {
        pTransactionIdStore->earliestTransactionIdIndex =
            (pTransactionIdStore->earliestTransactionIdIndex + 1) % pTransactionIdStore->maxTransactionIdsCount;
        return;
    }
    
    transactionIDCount = ( ( pTransactionIdStore->transactionIdCount + 1 ) > ( pTransactionIdStore->maxTransactionIdsCount ) )?pTransactionIdStore->maxTransactionIdsCount : ( pTransactionIdStore->transactionIdCount + 1 );

    pTransactionIdStore->transactionIdCount = transactionIDCount;
}

/*------------------------------------------------------------------------------------------------------------------*/

/* Ice_transactionIdStoreHasId - Checks if the transaction is present in the Transaction ID Store. */

static bool Ice_transactionIdStoreHasId( TransactionIdStore_t * pTransactionIdStore, uint8_t * transactionId )
{
    bool idFound = false;
    int i, j;

    if( pTransactionIdStore != NULL )
    {
        for (i = pTransactionIdStore->earliestTransactionIdIndex, j = 0; j < pTransactionIdStore->maxTransactionIdsCount && !idFound; ++j) {
            if ( memcmp( transactionId, pTransactionIdStore->transactionIds + i * STUN_TRANSACTION_ID_LEN, STUN_TRANSACTION_ID_LEN ) == 0) {
                idFound = true;
            }
            i = (i + 1) % pTransactionIdStore->maxTransactionIdsCount;
        }
    }
    return idFound;
}

/*------------------------------------------------------------------------------------------------------------------*/


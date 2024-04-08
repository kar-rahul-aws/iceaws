#ifndef ICE_API_H
#define ICE_API_H

/* *INDENT-OFF* */
#ifdef __cplusplus
    extern "C" {
#endif
/* *INDENT-ON* */

/* Standard includes. */
#include <stdint.h>
#include <stddef.h>

#include "ice_data_types.h"

/*-----------------------------------------------------------*/

IceResult_t Ice_CreateIceAgent( IceAgent_t * pIceAgent, char * localUsername, char * localPassword, char * remoteUsername, char * remotePassword, TransactionIdStore_t * pBuffer );

IceResult_t Ice_AddHostCandidate( const IceIPAddress_t ipAddr, IceAgent_t * pIceAgent );

IceResult_t Ice_AddSrflxCandidate( const IceIPAddress_t ipAddr, IceAgent_t * pIceAgent, IceServer_t * pIceServer, uint8_t * pStunMessageBuffer );

IceResult_t Ice_InsertLocalCandidate( IceAgent_t * pIceAgent, IceCandidate_t * pCandidate );

IceResult_t Ice_AddRemoteCandidate( IceAgent_t * pIceAgent, IceCandidateType_t iceCandidateType, const IceIPAddress_t ipAddr, IceSocketProtocol_t remoteProtocol, const uint32_t priority );

IceResult_t Ice_InsertRemoteCandidate( IceAgent_t * pIceAgent, IceCandidate_t * pCandidate );

IceResult_t Ice_CheckPeerReflexiveCandidate( IceAgent_t * pIceAgent, IceIPAddress_t pIpAddr, uint32_t priority );

IceResult_t Ice_CreateCandidatePair( IceAgent_t * pIceAgent, IceCandidate_t * pLocalCandidate, IceCandidate_t * pRemoteCandidate );

IceResult_t Ice_UpdateSrflxCandidateAddress( IceAgent_t * pIceAgent,IceCandidate_t * pCandidate, const IceIPAddress_t * pIpAddr );

IceResult_t Ice_InitializeStunPacket( StunContext_t * pStunCxt, uint8_t * transactionId, uint8_t * pStunMessageBuffer, StunHeader_t * pStunHeader, uint8_t isGenerateTransactionID, uint8_t isStunBindingRequest );

IceResult_t Ice_PackageStunPacket( StunContext_t * pStunCxt, uint8_t * password, uint32_t passwordLen );

IceResult_t Ice_CreateRequestForSrflxCandidate( IceAgent_t * pIceAgent, uint8_t * pStunMessageBuffer );

IceResult_t Ice_CreateRequestForNominatingValidCandidatePair( IceAgent_t * pIceAgent, uint8_t * pStunMessageBuffer, IceCandidatePair_t * pIceCandidatePair );

IceResult_t Ice_CreateRequestForConnectivityCheck( IceAgent_t * pIceAgent, uint8_t * pStunMessageBuffer );

IceResult_t Ice_CreateResponseForRequest( IceAgent_t * pIceAgent, uint8_t * pStunMessageBuffer, IceIPAddress_t * pSrcAddr );

IceResult_t Ice_DeserializeStunPacket( StunContext_t * pStunCxt, StunHeader_t * pStunHeader, StunAttribute_t * pStunAttribute, StunAttributeAddress_t * pStunAttributeAddress, uint32_t priority );

IceResult_t Ice_HandleStunResponse( IceAgent_t * pIceAgent, uint8_t * pStunMessageBuffer, uint8_t pStunMessageBufferLength, IceCandidate_t * pLocalCandidate , IceIPAddress_t * pSrcAddr, IceCandidatePair_t * pIceCandidatePair );

IceResult_t Ice_HandleServerReflexiveCandidateResponse( IceAgent_t * pIceAgent, StunAttributeAddress_t * pStunMappedAddress, IceCandidate_t * pLocalCandidate );


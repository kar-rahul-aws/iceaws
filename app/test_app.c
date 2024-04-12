/* Standard includes. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Ice incluudes. */
#include "../ice_api.h"
#include "../ice_data_types.h"

typedef enum RequestType{
    NOMINATING_CANDIDATE,
    CONNECTIVITY_CHECK,
    RESPONSE_FOR_REQUEST
} RequestType_t;

IceCandidate_t localCandidates[ICE_MAX_LOCAL_CANDIDATE_COUNT] = { 0 };
IceCandidate_t remoteCandidates[ICE_MAX_REMOTE_CANDIDATE_COUNT] = { 0 };
IceCandidatePair_t candidatePairs[ICE_MAX_CANDIDATE_PAIR_COUNT] = { 0 };
TransactionIdStore_t buffer[MAX_STORED_TRANSACTION_ID_COUNT] = { 0 };

void IceAgent_Init( IceAgent_t * iceAgent )
{
    IceResult_t result;

    char str1[] = "local", str2[] = "abc123", str3[] = "remote", str4[] = "xyz789";
    char str5[] = "remote:local";

    result = Ice_CreateIceAgent( iceAgent, str1, str2, str3, str4, str5, buffer );
    
    if( result == ICE_RESULT_OK )
    {
        int i;

        for( i = 0; i<ICE_MAX_LOCAL_CANDIDATE_COUNT; i++ )
        {
            iceAgent->localCandidates[i] = &localCandidates[i];
        }
        for( i = 0; i<ICE_MAX_REMOTE_CANDIDATE_COUNT; i++ )
        {
            iceAgent->remoteCandidates[i] = &remoteCandidates[i];
        }
        for( i = 0; i<ICE_MAX_CANDIDATE_PAIR_COUNT; i++ )
        {
            iceAgent->iceCandidatePairs[i] = &candidatePairs[i];
        }
    }
    else
    {
        printf("Creation of Ice Agent failed.\n");
    }
}

void Generate_HostCandidate( IceAgent_t * iceAgent )
{
    printf( "\nAdding Local Host candidates\n\n");

    IceResult_t result ;
    StunAttributeAddress_t stunAddress1, stunAddress2;
    IceIPAddress_t iceIpAddress1, iceIpAddress2;

    uint8_t ipAddress1V6[] = { 0x20, 0x01, 0x0D, 0xB8, 0x12, 0x34, 0x56, 0x78,
                                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 }; 
    uint8_t ipAddress2V6[] = { 0x21, 0x02, 0x0D, 0xB8, 0x12, 0x34, 0x56, 0x78,
                                0x00, 0x11, 0x52, 0x33, 0x44, 0x56, 0x66, 0x77 };
                              
    /* Initialise ICE IP address */    
    stunAddress1.family = STUN_ADDRESS_IPv6;
    stunAddress1.port = 32853;
    memcpy( stunAddress1.address, ipAddress1V6, STUN_IPV6_ADDRESS_SIZE );
    
    iceIpAddress1.ipAddress = stunAddress1;
    iceIpAddress1.isPointToPoint = 0;
                            
    stunAddress2.family = STUN_ADDRESS_IPv6;
    stunAddress2.port = 12345;
    memcpy( stunAddress2.address, ipAddress2V6, STUN_IPV6_ADDRESS_SIZE );
    
    /* Initialise ICE IP address */
    iceIpAddress2.ipAddress = stunAddress2;
    iceIpAddress2.isPointToPoint = 1;
    
    result = Ice_AddHostCandidate( iceIpAddress1, iceAgent );

    if( result == ICE_RESULT_OK )
    {
        printf("Local Candidate --> Port : %d\n", iceAgent->localCandidates[ 0 ]->ipAddress.ipAddress.port );
    }
    else
    {
        printf( "\nAdding host candidate 1 failed\n" );
    }

    result = Ice_AddHostCandidate( iceIpAddress2, iceAgent );
    
    if( result == ICE_RESULT_OK )
    {
        printf("Local Candidate --> Port : %d\n", iceAgent->localCandidates[ 1 ]->ipAddress.ipAddress.port );
    }
    else
    {
        printf( "\nAdding host candidate 2 failed\n" );
    }
}

void Generate_SrflxCandidate( IceAgent_t * iceAgent )
{
    printf( "\nAdding Local Srflx candidates\n");

    IceResult_t result ;
    StunAttributeAddress_t stunAddress;
    IceIPAddress_t iceIpAddress;
    uint8_t stunMessageBuffer[ 1024 ] = { 0 };
    int i;

    uint8_t ipAddressV6[] = { 0x20, 0x01, 0x0D, 0xB8, 0x12, 0x34, 0x56, 0x78,
                              0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };

    uint8_t transactionId[] = { 0xB7, 0xE7, 0xA7, 0x01, 0xBC, 0x34,
                                0xD6, 0x86, 0xFA, 0x87, 0xDF, 0xAE };

    /* Initialise ICE IP address */
    stunAddress.family = STUN_ADDRESS_IPv6;
    stunAddress.port = 48523;
    memcpy( stunAddress.address, ipAddressV6, STUN_IPV6_ADDRESS_SIZE );
    
    iceIpAddress.ipAddress = stunAddress;
    iceIpAddress.isPointToPoint = 0;

    result = Ice_AddSrflxCandidate( iceIpAddress, iceAgent, stunMessageBuffer, transactionId );

    if( result == ICE_RESULT_OK )
    {
        printf("\nLocal Candidate --> Port %d\n", iceAgent->localCandidates[ 2 ]->ipAddress.ipAddress.port );
        
        printf( "\nSerialized Message for Srflx request :\n\n" );
        
        for( i=0 ; i < 1024; i++ )
        {
            printf( "0x%02x ", stunMessageBuffer[ i ] );
        }

        printf(" \n\nTransaction Id Count %d",iceAgent->pStunBindingRequestTransactionIdStore->transactionIdCount );
    }
    else
    {
        printf( "Adding SRFLX csandidate failed\n" );
    }
}

void Generate_RemoteCandidate( IceAgent_t * iceAgent )
{
    printf( "\n\nAdding Remote candidates\n\n");
    
    IceResult_t result ;
    StunAttributeAddress_t stunAddress;
    IceIPAddress_t iceIpAddress;

    uint8_t ipAddressV6[] = { 0x20, 0x01, 0x0D, 0xB8, 0x12, 0x34, 0x56, 0x78,
                              0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 }; 

    /* Initialise ICE IP address */    
    stunAddress.family = STUN_ADDRESS_IPv6;
    stunAddress.port = 54321;
    memcpy( stunAddress.address, ipAddressV6, STUN_IPV6_ADDRESS_SIZE );
    
    iceIpAddress.ipAddress = stunAddress;
    iceIpAddress.isPointToPoint = 0;
    
    result = Ice_AddRemoteCandidate( iceAgent, ICE_CANDIDATE_TYPE_SERVER_REFLEXIVE, iceIpAddress, ICE_SOCKET_PROTOCOL_TCP, 5 );

    if( result == ICE_RESULT_OK )
    {
        printf("Remote Candidate --> Port %d\n", iceAgent->remoteCandidates[ 0 ]->ipAddress.ipAddress.port );
    }
    else
    {
        printf( "Adding remote candidate failed\n" );
    }
}

void Display_CandidatePairs( IceAgent_t * iceAgent )
{
    printf( "\n\nPrinting Candidate Pairs\n" );
    int i;
    for( i = 0; i < ICE_MAX_CANDIDATE_PAIR_COUNT; i++ )
    {
        if( iceAgent->iceCandidatePairs[i]->state != ICE_CANDIDATE_PAIR_STATE_INVALID )
        {
            printf( "\nLocal Candidate Port %d--> Remote Candidate Port : %d\n", iceAgent->iceCandidatePairs[i]->local->ipAddress.ipAddress.port , iceAgent->iceCandidatePairs[i]->remote->ipAddress.ipAddress.port );
        }
        else
        {
            break;
        }
    }
}

void Generate_StunRequests( IceAgent_t * iceAgent , RequestType_t index )
{
    IceResult_t result ;
    int i;
    uint8_t stunMessageBuffer[ 1024 ] = { 0 };
    uint8_t transactionId[] = { 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
                                0xA8, 0xA9, 0xAA, 0x87, 0xDF, 0xAE };

    switch( index ){
        case NOMINATING_CANDIDATE:
        {
            result = Ice_CreateRequestForNominatingValidCandidatePair( iceAgent, stunMessageBuffer, iceAgent->iceCandidatePairs[0], transactionId );
            if( result == ICE_RESULT_OK )
            {
                printf(" Nominating candidate pair : Local Candidate Port %d --> Remote Candidate Port %d \n",iceAgent->iceCandidatePairs[0]->local->ipAddress.ipAddress.port, iceAgent->iceCandidatePairs[0]->remote->ipAddress.ipAddress.port );
                
                printf( "\nSerialized Message for Nominating Candidate Pair :\n\n" );
        
                for( i=0 ; i < 1024; i++ )
                {
                    printf( "0x%02x ", stunMessageBuffer[ i ] );
                }
            }
            else
            {
                printf("Stun Request creation failed for Nominating Candidate Pair %d .\n", result );
            }
        }
            break;
        case CONNECTIVITY_CHECK:
        {
            result = Ice_CreateRequestForConnectivityCheck( iceAgent, stunMessageBuffer, transactionId );
            if( result == ICE_RESULT_OK )
            {
                printf( "\nSerialized Message for Connectivity check :\n\n" );
        
                for( i=0 ; i < 1024; i++ )
                {
                    printf( "0x%02x ", stunMessageBuffer[ i ] );
                }
            }
            else
            {
                printf("Stun Request creation failed for Connectivity Check. %d \n" ,  result );
            }
        }
            break;
        case RESPONSE_FOR_REQUEST:
        {
            result = Ice_CreateResponseForRequest( iceAgent, stunMessageBuffer, &(iceAgent->iceCandidatePairs[1]->remote->ipAddress), transactionId );
            if( result == ICE_RESULT_OK )
            {
                printf( "\nSerialized Message for Response to Request from Remote candidate :\n\n" );
        
                for( i=0 ; i < 1024; i++ )
                {
                    printf( "0x%02x ", stunMessageBuffer[ i ] );
                }
            }
            else
            {
                printf("Stun Request creation failed  for Response to Request from Remote candidate. %d \n" ,  result );
            }
        }
        default: 
            break;
    }
}

void Handle_StunResponse( IceAgent_t * iceAgent )
{
    printf( "\nHandling Stun Response\n\n" );
    
    uint8_t stunMessageBuffer[ 1024 ] = { 0 };
    uint8_t transactionId[] = { 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
                                0xA8, 0xA9, 0xAA, 0x87, 0xDF, 0xAE };
    IceResult_t result;
    
    result = Ice_CreateResponseForRequest( iceAgent, stunMessageBuffer, &(iceAgent->iceCandidatePairs[1]->remote->ipAddress), transactionId );
    
    result = Ice_HandleStunResponse( iceAgent, stunMessageBuffer, 88, transactionId, iceAgent->iceCandidatePairs[1]->local, &( iceAgent->iceCandidatePairs[1]->local->ipAddress ), iceAgent->iceCandidatePairs[1] );
    
    switch( result )
    {
        case ICE_RESULT_UPDATE_SRFLX_CANDIDATE:
        {
            Display_CandidatePairs( iceAgent );
        }
            break;
        case ICE_RESULT_CANDIDATE_PAIR_READY:
        {
            printf( "Candidate Pair is Nominated and Ready for Data Transfer : Local Candidate Port : %d --> Remote Candidate Port : %d\n", iceAgent->iceCandidatePairs[1]->local->ipAddress.ipAddress.port, iceAgent->iceCandidatePairs[1]->remote->ipAddress.ipAddress.port );
        }
            break;
        default:
            break;
    }
}

int main( void )
{
    IceAgent_t *iceAgent = malloc(sizeof(struct IceAgent));

    IceAgent_Init( iceAgent );

    Generate_HostCandidate( iceAgent );

    Generate_SrflxCandidate( iceAgent );

    Generate_RemoteCandidate( iceAgent );

    Display_CandidatePairs( iceAgent );

    /* Test Stun Request creation for Nominating Candidate Pair. */
    Generate_StunRequests( iceAgent, 0 );

    /* Test Stun Request creation for Connectivity Check. */
    Generate_StunRequests( iceAgent, 1 );

    /* Test Stun Request creation for Response for Remote candidate requests. */
    Generate_StunRequests( iceAgent, 2 );

    Handle_StunResponse(iceAgent );

    printf("\n");

    return 0;
}


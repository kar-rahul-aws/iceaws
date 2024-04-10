/* Standard includes. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Ice incluudes. */
#include "../ice_api.h"
#include "../ice_data_types.h"

IceCandidate_t localCandidates[ICE_MAX_LOCAL_CANDIDATE_COUNT] = { 0 };
IceCandidate_t remoteCandidates[ICE_MAX_REMOTE_CANDIDATE_COUNT] = { 0 };
TransactionIdStore_t buffer[MAX_STORED_TRANSACTION_ID_COUNT] = { 0 };

void IceAgent_Init( IceAgent_t *iceAgent )
{
    IceResult_t result;

    char str1[] = "local", str2[] = "abc123", str3[] = "remote", str4[] = "xyz789";

    result = Ice_CreateIceAgent( iceAgent, str1, str2, str3, str4, buffer );
    
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
    }
    else
    {
        printf("Creation of Ice Agent failed.\n");
    }
}

void Generate_HostCandidate( IceAgent_t *iceAgent )
{
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
        printf("%d\n",iceAgent->localCandidates[ 0 ]->ipAddress.ipAddress.port );
    }
    else
    {
        printf( "Adding host candidate 1 failed\n" );
    }

    result = Ice_AddHostCandidate( iceIpAddress2, iceAgent );
    
    if( result == ICE_RESULT_OK )
    {
        printf("%d\n",iceAgent->localCandidates[ 1 ]->ipAddress.ipAddress.port );
    }
    else
    {
        printf( "Adding host candidate 2 failed\n" );
    }
}

void Generate_SrflxCandidate( IceAgent_t *iceAgent )
{
    IceResult_t result ;
    StunAttributeAddress_t stunAddress;
    IceIPAddress_t iceIpAddress;
    uint8_t stunMessageBuffer[ 1024 ] = { 0 };
    int i;

    uint8_t ipAddressV6[] = { 0x20, 0x01, 0x0D, 0xB8, 0x12, 0x34, 0x56, 0x78,
                                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };

    
    /* Initialise ICE IP address */
    stunAddress.family = STUN_ADDRESS_IPv6;
    stunAddress.port = 48523;
    memcpy( stunAddress.address, ipAddressV6, STUN_IPV6_ADDRESS_SIZE );
    
    iceIpAddress.ipAddress = stunAddress;
    iceIpAddress.isPointToPoint = 0;

    result = Ice_AddSrflxCandidate( iceIpAddress, iceAgent, stunMessageBuffer );

    if( result == ICE_RESULT_OK )
    {
        printf("\n%d\n",iceAgent->localCandidates[ 2 ]->ipAddress.ipAddress.port );
        
        printf( "\nSerialized Message :\n" );

    }
    else
    {
        printf( "Adding SRFLX csandidate failed\n" );
    }
}

void Generate_RemoteCandidate( IceAgent_t *iceAgent )
{
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
        printf("%d\n",iceAgent->remoteCandidates[ 0 ]->ipAddress.ipAddress.port );
    }
    else
    {
        printf( "Adding remote candidate failed\n" );
    }
}

int main( void )
{
    IceAgent_t *iceAgent = malloc(sizeof(struct IceAgent));

    IceAgent_Init( iceAgent );

    Generate_HostCandidate( iceAgent );

    Generate_SrflxCandidate( iceAgent );

    Generate_RemoteCandidate( iceAgent );

    return 0;
}
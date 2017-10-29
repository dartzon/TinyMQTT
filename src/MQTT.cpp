// =============================================================================
// Copyright 2017 Othmane AIT EL CADI
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// =============================================================================

/*
 * \file      MQTT.cpp
 *
 * \author    Othmane AIT EL CADI - dartzon@gmail.com
 * \date      28-05-2017
 */

#include "MQTT.h"
#include "MQTTNumeric.h"
#include "MQTTStringUtils.h"
#include <cstring>
#include <cstdio>

namespace Ocelot
{

void MQTT::describeControlPacket(const MQTTControlPacket& ctrlPkt,
                                 MQTTControlPacketDescriptor& ctrlDescr)
{
    // =============================================================
    // Compute fixed header length.
    // =============================================================
    uint32_t remainingLength = *(reinterpret_cast<uint32_t*>(ctrlPkt.m_fixedHeader.m_pData +
                                                             sizeof(uint8_t)));
    const uint8_t remainingLengthSize = MQTT::decodeRemainingLength(remainingLength);

    // Set the remaining length.
    ctrlDescr.m_remainingLength = remainingLength;

    // Fixed header length :
    //   * Packet type + flags (1 byte).
    //   * Reamining length (Max. 4 bytes).
    ctrlDescr.m_fixedHeaderSize = 1 + remainingLengthSize;

    // =============================================================
    // Compute variable header length + payload length.
    // =============================================================

    // Compute the control packet's type.
    ctrlDescr.m_type = static_cast<MQTTControlPacketType>(
        (*reinterpret_cast<const uint8_t*>(ctrlPkt.m_fixedHeader.m_pData) >> 4) & 0x0F);

    switch(ctrlDescr.m_type)
    {
    case MQTTControlPacketType::CONNECT:
        ctrlDescr.m_variableHeaderSize = 10; // Variable header length.
        ctrlDescr.m_payloadSize = (remainingLength - 10); // Payload length.
        break;

    case MQTTControlPacketType::PUBLISH:
    {
        // Variable header length :
        //   * Packet ID (2 bytes).
        //   * Subject's length (UTF-8 string length : 2 bytes).
        uint32_t varHeaderSize = sizeof(uint16_t) * 2;
        const uint16_t subjectLen = *reinterpret_cast<uint16_t*>(ctrlPkt.m_variableHeader.m_pData);
        varHeaderSize += MQTT::toLittleEndian(subjectLen);

        ctrlDescr.m_variableHeaderSize = varHeaderSize; // Variable header length.
        ctrlDescr.m_payloadSize = (remainingLength - varHeaderSize); // Payload length.
    }
    break;

    case MQTTControlPacketType::SUBSCRIBE:
    case MQTTControlPacketType::SUBACK:
    case MQTTControlPacketType::UNSUBSCRIBE:
        // Variable header length :
        //   * Packet ID (2 bytes).
        ctrlDescr.m_variableHeaderSize = 2; // Variable header length.
        ctrlDescr.m_payloadSize = (remainingLength - 2); // Payload length.
        break;

    default: break;
    }

    ctrlDescr.m_totalPacketSize = ctrlDescr.m_fixedHeaderSize + ctrlDescr.m_variableHeaderSize +
                                  ctrlDescr.m_payloadSize;
}

// -------------------------------------------------------------------------------------------------

void MQTT::debugPrintControlPacket(MQTTControlPacketDescriptor& ctrlDescr)
{
#ifdef OCELOT_DEBUG

    printf("+-------------------------------------------\n");
    printf("| DEBUG INFO - PACKET INFO : \n");

    printf("|\tPACKET TYPE           : ");
    switch(ctrlDescr.m_type)
    {
    case MQTTControlPacketType::RESERVED_START: printf("RESERVED, SHOULD NOT BE USED !!\n"); break;
    case MQTTControlPacketType::CONNECT: printf("CONNECT\n"); break;
    case MQTTControlPacketType::CONNACK:  printf("CONNACK\n"); break;
    case MQTTControlPacketType::PUBLISH:  printf("PUBLISH\n"); break;
    case MQTTControlPacketType::PUBACK:  printf("PUBACK\n"); break;
    case MQTTControlPacketType::PUBREC:  printf("PUBREC\n"); break;
    case MQTTControlPacketType::PUBREL:  printf("PUBREL\n"); break;
    case MQTTControlPacketType::PUBCOMP:  printf("PUBCOMP\n"); break;
    case MQTTControlPacketType::SUBSCRIBE:  printf("SUBSCRIBE\n"); break;
    case MQTTControlPacketType::SUBACK:  printf("SUBACK\n"); break;
    case MQTTControlPacketType::UNSUBSCRIBE:  printf("UNSUBSCRIBE\n"); break;
    case MQTTControlPacketType::UNSUBACK:  printf("UNSUBACK\n"); break;
    case MQTTControlPacketType::PINGREQ:  printf("PINGREQ\n"); break;
    case MQTTControlPacketType::PINGRESP:  printf("PINGRESP\n"); break;
    case MQTTControlPacketType::DISCONNECT:  printf("DISCONNECT\n"); break;
    case MQTTControlPacketType::RESERVED_END:  printf("RESERVED, SHOULD NOT BE USED !!\n"); break;
    }

    printf("|\tFIXED HEADER SIZE     : %u bytes\n", ctrlDescr.m_fixedHeaderSize);
    printf("|\tVARIABLE HEADER SIZE  : %u bytes\n", ctrlDescr.m_variableHeaderSize);
    printf("|\tPAYLOAD SIZE          : %u bytes\n", ctrlDescr.m_payloadSize);
    printf("+-------------------------------------------\n");
    printf("|\tTOTAL PACKET SIZE     : %u bytes\n", ctrlDescr.m_totalPacketSize);
    printf("+-------------------------------------------\n");

#endif
}

// -------------------------------------------------------------------------------------------------

uint8_t MQTT::createFixedHeader(MQTTFixedHeader& MQTTFxHeader,
                                const MQTTControlPacketType ctrlPktType, uint32_t remainingLength,
                                const uint8_t lowerQuadbit)
{
    uint8_t* MQTTPacketBuffer = MQTT::getGlobalMQTTPacketBuffer();

    MQTTFxHeader.m_pData = MQTTPacketBuffer;
    MQTTFxHeader.m_pData[0] = static_cast<uint8_t>(ctrlPktType) << 4 | lowerQuadbit;
    const uint8_t remainingLengthInBytes = MQTT::encodeRemainingLength(remainingLength);
    memcpy(MQTTFxHeader.m_pData + 1, &remainingLength, remainingLengthInBytes);

    return (1 + remainingLengthInBytes);
}

// -------------------------------------------------------------------------------------------------

void MQTT::createConnectPacket(MQTTControlPacket& MQTTConnectPkt,
                               const bool cleanSession, const bool willFlag,
                               const MQTTQoSLevel QoSLvl,
                               const bool willRetain, const bool pwdFlag, const bool usernameFlag,
                               const uint16_t keepAliveSec,
                               const char* pClientIDTxt, const size_t clientIDLength,
                               const char* pWillTopicTxt, const size_t willTopicLength,
                               const char* pWillMsgTxt, const size_t willMsgLength,
                               const char* pUsernameTxt, const size_t usernameLength,
                               const char* pPasswordTxt, const size_t passwordLength)
{
    const uint32_t payloadSize = (5 * sizeof(uint16_t)) + clientIDLength + willTopicLength +
                                 willMsgLength + usernameLength + passwordLength;

    // =============================================================
    // Create the FIXED header.
    // =============================================================
    MQTTFixedHeader& MQTTFxHeader = MQTTConnectPkt.m_fixedHeader;
    const uint8_t fxHeaderSize = createFixedHeader(MQTTFxHeader, MQTTControlPacketType::CONNECT,
                                                   10 + payloadSize);

    // =============================================================
    // Create the VARIABLE header.
    // =============================================================
    uint8_t* MQTTPacketBuffer = MQTT::getGlobalMQTTPacketBuffer();
    uint8_t* pVarHeaderData = MQTTPacketBuffer + fxHeaderSize;

    // Protocol name as UTF-8 string.
    pVarHeaderData[0] = 0x0;
    pVarHeaderData[1] = 4;
    pVarHeaderData[2] = 'M';
    pVarHeaderData[3] = 'Q';
    pVarHeaderData[4] = 'T';
    pVarHeaderData[5] = 'T';

#if MQTT_PROTOCOL_VERSION == 0x04
    // Protocol revision level (4 for MQTT 3.1.1).
    pVarHeaderData[6] = 4;

#else

#error This version of MQTT protocol is not supported

#endif

    // Connect flags (Figure 3.4 - Connect Flag bits).
    uint8_t connectFlags = 0;
    if(cleanSession == true)
    {
        // Set the clean session flag.
        connectFlags |= 2;
    }
    if(willFlag == true)
    {
        // Set the will flag.
        connectFlags |= 4;
    }
    // Set the will QoS flag (2 bits).
    connectFlags |= static_cast<uint8_t>(QoSLvl) << 3;

    if(willRetain == true)
    {
        // Set the will retain flag (2 bits).
        connectFlags |= 32;
    }
    if(usernameFlag == true)
    {
        // Set the username flag.
        connectFlags |= 128;
    }
    if(pwdFlag == true)
    {
        // Set the password flag.
        connectFlags |= 64;
    }

    pVarHeaderData[7] = connectFlags;

    // Keep alive (value in seconds).
    *(reinterpret_cast<uint16_t*>(pVarHeaderData + 8)) = MQTT::toBigEndian(keepAliveSec);

    MQTTConnectPkt.m_variableHeader.m_pData = pVarHeaderData;

    // =============================================================
    // Create the PAYLOAD.
    // =============================================================
    uint8_t* pPayloadData = pVarHeaderData + 10;
    uint32_t bytesShift = 0;

    bytesShift += storeUTF8String(pPayloadData + bytesShift, pClientIDTxt, clientIDLength);

    if(willFlag == true)
    {
        bytesShift += storeUTF8String(pPayloadData + bytesShift, pWillTopicTxt, willTopicLength);
        bytesShift += storeUTF8String(pPayloadData + bytesShift, pWillMsgTxt, willMsgLength);
    }

    if(usernameFlag == true)
    {
        bytesShift += storeUTF8String(pPayloadData + bytesShift, pUsernameTxt, usernameLength);
    }
    if(pwdFlag == true)
    {
        storeUTF8String(pPayloadData + bytesShift, pPasswordTxt, passwordLength);
    }

    // =============================================================
    // Compute total packet size.
    // =============================================================
    MQTTConnectPkt.m_totalPacketSize = fxHeaderSize + 10 + payloadSize;
}

// -------------------------------------------------------------------------------------------------

void MQTT::createConnAckPacket(MQTTControlPacket& MQTTConnectAckPkt,
                               const bool sessionPresent, const MQTTConnectReturnCode retCode)
{
    // =============================================================
    // Create the FIXED header.
    // =============================================================
    MQTTFixedHeader& MQTTFxHeader = MQTTConnectAckPkt.m_fixedHeader;
    const uint8_t fxHeaderSize = createFixedHeader(MQTTFxHeader, MQTTControlPacketType::CONNACK, 2);

    // =============================================================
    // Create the VARIABLE header.
    // =============================================================
    uint8_t* MQTTPacketBuffer = MQTT::getGlobalMQTTPacketBuffer();
    uint8_t* pVarHeaderData = MQTTPacketBuffer + fxHeaderSize;
    memset(pVarHeaderData, 0, 2);

    if(sessionPresent == true)
    {
        // Set the session present flag.
        pVarHeaderData[0] = 1;
    }

    pVarHeaderData[1] = static_cast<uint8_t>(retCode);

    MQTTConnectAckPkt.m_variableHeader.m_pData = pVarHeaderData;

    // =============================================================
    // Create the PAYLOAD.
    // =============================================================
    MQTTConnectAckPkt.m_pPayload = nullptr; // The CONNACK Packet has no payload.

    // =============================================================
    // Compute total packet size.
    // =============================================================
    MQTTConnectAckPkt.m_totalPacketSize = fxHeaderSize + 2;
}

// -------------------------------------------------------------------------------------------------

void MQTT::createPublishPacket(MQTTControlPacket& MQTTPubPkt,
                               const bool DUPFlag, const MQTTQoSLevel QoSLvl, const bool retainFlag,
                               const char* pTopicNameTxt, const size_t topicNameLength,
                               const uint16_t packetID,
                               const uint8_t* pPayloadData, const uint32_t payloadSize)
{

    // =============================================================
    // Create the FIXED header.
    // =============================================================
    uint8_t lowerQuadbit = 0;
    if(retainFlag == true)
    {
        lowerQuadbit = 1;
    }
    lowerQuadbit |= static_cast<uint8_t>(QoSLvl) << 1;
    if(DUPFlag == true)
    {
        lowerQuadbit |= 1 << 3;
    }

    uint32_t varHeaderSize = sizeof(uint16_t) + topicNameLength;
    if(packetID > 0)
    {
        varHeaderSize += sizeof(uint16_t);
    }

    MQTTFixedHeader& MQTTFxHeader = MQTTPubPkt.m_fixedHeader;
    const uint8_t fxHeaderSize = createFixedHeader(MQTTFxHeader, MQTTControlPacketType::PUBLISH,
                                                   varHeaderSize + payloadSize, lowerQuadbit);

    // =============================================================
    // Create the VARIABLE header.
    // =============================================================
    uint8_t* MQTTPacketBuffer = MQTT::getGlobalMQTTPacketBuffer();
    uint8_t* pVarHeaderData = MQTTPacketBuffer + fxHeaderSize;
    const uint32_t bytesShift = storeUTF8String(pVarHeaderData, pTopicNameTxt, topicNameLength);

    // Create the client identifier.
    if(packetID > 0)
    {
        *(reinterpret_cast<uint16_t*>(pVarHeaderData + bytesShift)) = MQTT::toBigEndian(packetID);
    }

    MQTTPubPkt.m_variableHeader.m_pData = pVarHeaderData;

    // =============================================================
    // Create the PAYLOAD.
    // =============================================================
    MQTTPubPkt.m_pPayload = pVarHeaderData + varHeaderSize;
    memcpy(MQTTPubPkt.m_pPayload, pPayloadData, payloadSize);

    // =============================================================
    // Compute total packet size.
    // =============================================================
    MQTTPubPkt.m_totalPacketSize = fxHeaderSize + varHeaderSize + payloadSize;
}

// -------------------------------------------------------------------------------------------------

void MQTT::createPubAckPacket(MQTTControlPacket& MQTTPubAckPkt, const uint16_t packetID)
{
    // =============================================================
    // Create the FIXED header.
    // =============================================================
    MQTTFixedHeader& MQTTFxHeader = MQTTPubAckPkt.m_fixedHeader;
    const uint8_t fxHeaderSize = createFixedHeader(MQTTFxHeader, MQTTControlPacketType::PUBACK, 2);

    // =============================================================
    // Create the VARIABLE header.
    // =============================================================
    uint8_t* MQTTPacketBuffer = MQTT::getGlobalMQTTPacketBuffer();
    uint8_t* pVarHeaderData = MQTTPacketBuffer + fxHeaderSize;
    *(reinterpret_cast<uint16_t*>(pVarHeaderData)) = MQTT::toBigEndian(packetID);

    MQTTPubAckPkt.m_variableHeader.m_pData = pVarHeaderData;

    // =============================================================
    // Create the PAYLOAD.
    // =============================================================
    MQTTPubAckPkt.m_pPayload = nullptr; // The PUBACK Packet has no payload.

    // =============================================================
    // Compute total packet size.
    // =============================================================
    MQTTPubAckPkt.m_totalPacketSize = fxHeaderSize + 2;
}

// -------------------------------------------------------------------------------------------------

void MQTT::createPubRecPacket(MQTTControlPacket& MQTTPubRecPkt, const uint16_t packetID)
{
    // =============================================================
    // Create the FIXED header.
    // =============================================================
    MQTTFixedHeader& MQTTFxHeader = MQTTPubRecPkt.m_fixedHeader;
    const uint8_t fxHeaderSize = createFixedHeader(MQTTFxHeader, MQTTControlPacketType::PUBREC, 2);

    // =============================================================
    // Create the VARIABLE header.
    // =============================================================
    uint8_t* MQTTPacketBuffer = MQTT::getGlobalMQTTPacketBuffer();
    uint8_t* pVarHeaderData = MQTTPacketBuffer + fxHeaderSize;
    *(reinterpret_cast<uint16_t*>(pVarHeaderData)) = MQTT::toBigEndian(packetID);

    MQTTPubRecPkt.m_variableHeader.m_pData = pVarHeaderData;

    // =============================================================
    // Create the PAYLOAD.
    // =============================================================
    MQTTPubRecPkt.m_pPayload = nullptr; // The PUBREC Packet has no payload.

    // =============================================================
    // Compute total packet size.
    // =============================================================
    MQTTPubRecPkt.m_totalPacketSize = fxHeaderSize + 2;
}

// -------------------------------------------------------------------------------------------------

void MQTT::createPubRelPacket(MQTTControlPacket& MQTTPubRelPkt, const uint16_t packetID)
{
    // =============================================================
    // Create the FIXED header.
    // =============================================================
    MQTTFixedHeader& MQTTFxHeader = MQTTPubRelPkt.m_fixedHeader;
    const uint8_t fxHeaderSize = createFixedHeader(MQTTFxHeader, MQTTControlPacketType::PUBREL, 2,
                                                   static_cast<uint8_t>(
                                                       MQTTControlPacketFlag::PUBREL_FLAG));

    // =============================================================
    // Create the VARIABLE header.
    // =============================================================
    uint8_t* MQTTPacketBuffer = MQTT::getGlobalMQTTPacketBuffer();
    uint8_t* pVarHeaderData = MQTTPacketBuffer + fxHeaderSize;
    *(reinterpret_cast<uint16_t*>(pVarHeaderData)) = MQTT::toBigEndian(packetID);

    MQTTPubRelPkt.m_variableHeader.m_pData = pVarHeaderData;

    // =============================================================
    // Create the PAYLOAD.
    // =============================================================
    MQTTPubRelPkt.m_pPayload = nullptr; // The PUBREL Packet has no payload.

    // =============================================================
    // Compute total packet size.
    // =============================================================
    MQTTPubRelPkt.m_totalPacketSize = fxHeaderSize + 2;
}

// -------------------------------------------------------------------------------------------------

void MQTT::createPubCompPacket(MQTTControlPacket& MQTTPubCompPkt, const uint16_t packetID)
{
    // =============================================================
    // Create the FIXED header.
    // =============================================================
    MQTTFixedHeader& MQTTFxHeader = MQTTPubCompPkt.m_fixedHeader;
    const uint8_t fxHeaderSize = createFixedHeader(MQTTFxHeader, MQTTControlPacketType::PUBCOMP, 2);

    // =============================================================
    // Create the VARIABLE header.
    // =============================================================
    uint8_t* MQTTPacketBuffer = MQTT::getGlobalMQTTPacketBuffer();
    uint8_t* pVarHeaderData = MQTTPacketBuffer + fxHeaderSize;
    *(reinterpret_cast<uint16_t*>(pVarHeaderData)) = MQTT::toBigEndian(packetID);

    MQTTPubCompPkt.m_variableHeader.m_pData = pVarHeaderData;

    // =============================================================
    // Create the PAYLOAD.
    // =============================================================
    MQTTPubCompPkt.m_pPayload = nullptr; // The PUBCOMP Packet has no payload.

    // =============================================================
    // Compute total packet size.
    // =============================================================
    MQTTPubCompPkt.m_totalPacketSize = fxHeaderSize + 2;
}

// -------------------------------------------------------------------------------------------------

void MQTT::createSubscribePacket(MQTTControlPacket& MQTTSubscribePkt,
                                 const uint16_t packetID,
                                 const char** ppTopicFiltersTxt,
                                 const uint16_t* pTopicFiltersLengths,
                                 const MQTTQoSLevel* pRequestedQoSs,
                                 const uint32_t countTopicFilters)
{
    uint32_t payloadSize = 0;
    for(uint16_t idx = 0; idx < countTopicFilters; ++idx)
    {
        // Size of MQTT UTF-8 string + 1 requested QoS byte.
        payloadSize += (2 + pTopicFiltersLengths[idx]) + 1;
    }

    // =============================================================
    // Create the FIXED header.
    // =============================================================
    MQTTFixedHeader& MQTTFxHeader = MQTTSubscribePkt.m_fixedHeader;
    const uint8_t fxHeaderSize = createFixedHeader(MQTTFxHeader, MQTTControlPacketType::SUBSCRIBE,
                                                   payloadSize + 2,
                                                   static_cast<uint8_t>(
                                                       MQTTControlPacketFlag::SUBSCRIBE_FLAG));

    // =============================================================
    // Create the VARIABLE header.
    // =============================================================

    // Create the client identifier.
    uint8_t* MQTTPacketBuffer = MQTT::getGlobalMQTTPacketBuffer();
    uint8_t* pVarHeaderData = MQTTPacketBuffer + fxHeaderSize;
    *(reinterpret_cast<uint16_t*>(pVarHeaderData)) = MQTT::toBigEndian(packetID);

    MQTTSubscribePkt.m_variableHeader.m_pData = pVarHeaderData;

    // =============================================================
    // Create the PAYLOAD.
    // =============================================================

    uint8_t* pPayloadData = pVarHeaderData + 2;
    uint32_t bytesShift = 0;
    for(uint32_t idxFilter = 0; idxFilter < countTopicFilters; ++idxFilter)
    {
        bytesShift += storeUTF8String(pPayloadData + bytesShift,
                                      ppTopicFiltersTxt[idxFilter],
                                      pTopicFiltersLengths[idxFilter]);
        bytesShift += MQTT::storeNumber(pPayloadData + bytesShift,
                                        static_cast<uint8_t>(pRequestedQoSs[idxFilter]));
    }

    MQTTSubscribePkt.m_pPayload = pPayloadData;

    // =============================================================
    // Compute total packet size.
    // =============================================================
    MQTTSubscribePkt.m_totalPacketSize = fxHeaderSize + 2 + payloadSize;
}

// -------------------------------------------------------------------------------------------------

// 3.9 SUBACK – Subscribe acknowledgement.
void MQTT::createSubAckPacket(MQTTControlPacket& MQTTSubAckPkt,
                              const uint16_t packetID,
                              const MQTTQoSLevel* pReturnCodes, const uint32_t countReturnCodes)
{
    // =============================================================
    // Create the FIXED header.
    // =============================================================
    MQTTFixedHeader& MQTTFxHeader = MQTTSubAckPkt.m_fixedHeader;
    const uint8_t fxHeaderSize = createFixedHeader(MQTTFxHeader, MQTTControlPacketType::SUBACK,
                                                   2 + countReturnCodes);

    // =============================================================
    // Create the VARIABLE header.
    // =============================================================

    // Create the client identifier.
    uint8_t* MQTTPacketBuffer = MQTT::getGlobalMQTTPacketBuffer();
    uint8_t* pVarHeaderData = MQTTPacketBuffer + fxHeaderSize;
    *(reinterpret_cast<uint16_t*>(pVarHeaderData)) = MQTT::toBigEndian(packetID);

    MQTTSubAckPkt.m_variableHeader.m_pData = pVarHeaderData;

    // =============================================================
    // Create the PAYLOAD.
    // =============================================================
    MQTTSubAckPkt.m_pPayload = pVarHeaderData + 2;
    memcpy(MQTTSubAckPkt.m_pPayload, pReturnCodes, countReturnCodes);

    // =============================================================
    // Compute total packet size.
    // =============================================================
    MQTTSubAckPkt.m_totalPacketSize = fxHeaderSize + 2 + countReturnCodes;
}

// -------------------------------------------------------------------------------------------------

void MQTT::createUnsubscribePacket(MQTTControlPacket& MQTTUnsubscribePkt,
                                   const uint16_t packetID,
                                   const char** ppTopicFiltersTxt,
                                   const uint16_t* pTopicFiltersLengths,
                                   const uint32_t countTopicFilters)
{
    uint32_t payloadSize = 0; // 2 bytes for the variable header.
    for(uint16_t idx = 0; idx < countTopicFilters; ++idx)
    {
        // Size of MQTT UTF-8 string.
        payloadSize += (2 + pTopicFiltersLengths[idx]);
    }

    // =============================================================
    // Create the FIXED header.
    // =============================================================
    MQTTFixedHeader& MQTTFxHeader = MQTTUnsubscribePkt.m_fixedHeader;
    const uint8_t fxHeaderSize = createFixedHeader(MQTTFxHeader, MQTTControlPacketType::UNSUBSCRIBE,
                                                   2 + payloadSize,
                                                   static_cast<uint8_t>(
                                                       MQTTControlPacketFlag::UNSUBSCRIBE_FLAG));

    // =============================================================
    // Create the VARIABLE header.
    // =============================================================

    // Create the client identifier.
    uint8_t* MQTTPacketBuffer = MQTT::getGlobalMQTTPacketBuffer();
    uint8_t* pVarHeaderData = MQTTPacketBuffer + fxHeaderSize;
    *(reinterpret_cast<uint16_t*>(pVarHeaderData)) = MQTT::toBigEndian(packetID);

    MQTTUnsubscribePkt.m_variableHeader.m_pData = pVarHeaderData;

    // =============================================================
    // Create the PAYLOAD.
    // =============================================================

    uint8_t* pPayloadData = pVarHeaderData + 2;
    uint32_t bytesShift = 0;
    for(uint32_t idxFilter = 0; idxFilter < countTopicFilters; ++idxFilter)
    {
        bytesShift += storeUTF8String(pPayloadData + bytesShift,
                                      ppTopicFiltersTxt[idxFilter],
                                      pTopicFiltersLengths[idxFilter]);
    }

    MQTTUnsubscribePkt.m_pPayload = pPayloadData;

    // =============================================================
    // Compute total packet size.
    // =============================================================
    MQTTUnsubscribePkt.m_totalPacketSize = fxHeaderSize + 2 + payloadSize;
}

// -------------------------------------------------------------------------------------------------

void MQTT::createUnsubAckPacket(MQTTControlPacket& MQTTUnSubAckPkt,
                                const uint16_t packetID)
{
    // =============================================================
    // Create the FIXED header.
    // =============================================================
    MQTTFixedHeader& MQTTFxHeader = MQTTUnSubAckPkt.m_fixedHeader;
    const uint8_t fxHeaderSize = createFixedHeader(MQTTFxHeader,
                                                   MQTTControlPacketType::UNSUBACK, 2);

    // =============================================================
    // Create the VARIABLE header.
    // =============================================================
    uint8_t* MQTTPacketBuffer = MQTT::getGlobalMQTTPacketBuffer();
    uint8_t* pVarHeaderData = MQTTPacketBuffer + fxHeaderSize;
    *(reinterpret_cast<uint16_t*>(pVarHeaderData)) = MQTT::toBigEndian(packetID);

    MQTTUnSubAckPkt.m_variableHeader.m_pData = pVarHeaderData;

    // =============================================================
    // Create the PAYLOAD.
    // =============================================================
    MQTTUnSubAckPkt.m_pPayload = nullptr; // The UNSUBACK Packet has no payload.

    // =============================================================
    // Compute total packet size.
    // =============================================================
    MQTTUnSubAckPkt.m_totalPacketSize = fxHeaderSize + 2;
}

// -------------------------------------------------------------------------------------------------

void MQTT::createPingReqPacket(MQTTControlPacket& MQTTPingReqPkt)
{
    // =============================================================
    // Create the FIXED header.
    // =============================================================
    MQTTFixedHeader& MQTTFxHeader = MQTTPingReqPkt.m_fixedHeader;
    const uint8_t fxHeaderSize = createFixedHeader(MQTTFxHeader, MQTTControlPacketType::PINGREQ, 0);

    // =============================================================
    // Create the VARIABLE header.
    // =============================================================
    MQTTPingReqPkt.m_variableHeader.m_pData = nullptr; // The PINGREQ Packet has no variable header.

    // =============================================================
    // Create the PAYLOAD.
    // =============================================================
    MQTTPingReqPkt.m_pPayload = nullptr;

    // =============================================================
    // Compute total packet size.
    // =============================================================
    MQTTPingReqPkt.m_totalPacketSize = fxHeaderSize;
}

// -------------------------------------------------------------------------------------------------

void MQTT::createPingRespPacket(MQTTControlPacket& MQTTPingRespPkt)
{
    // =============================================================
    // Create the FIXED header.
    // =============================================================
    MQTTFixedHeader& MQTTFxHeader = MQTTPingRespPkt.m_fixedHeader;
    const uint8_t fxHeaderSize = createFixedHeader(MQTTFxHeader, MQTTControlPacketType::PINGRESP,
                                                   0);

    // =============================================================
    // Create the VARIABLE header.
    // =============================================================
    // The PINGRESP Packet has no variable header.
    MQTTPingRespPkt.m_variableHeader.m_pData = nullptr;

    // =============================================================
    // Create the PAYLOAD.
    // =============================================================
    MQTTPingRespPkt.m_pPayload = nullptr; // The PINGRESP Packet has no payload.

    // =============================================================
    // Compute total packet size.
    // =============================================================
    MQTTPingRespPkt.m_totalPacketSize = fxHeaderSize;
}

// -------------------------------------------------------------------------------------------------

void MQTT::createDisconnectPacket(MQTTControlPacket& MQTTDisconnectPkt)
{
    // =============================================================
    // Create the FIXED header.
    // =============================================================
    MQTTFixedHeader& MQTTFxHeader = MQTTDisconnectPkt.m_fixedHeader;
    const uint8_t fxHeaderSize = createFixedHeader(MQTTFxHeader, MQTTControlPacketType::DISCONNECT,
                                                   0);

    // =============================================================
    // Create the VARIABLE header.
    // =============================================================
    // The DISCONNECT Packet has no variable header.
    MQTTDisconnectPkt.m_variableHeader.m_pData = nullptr;

    // =============================================================
    // Create the PAYLOAD.
    // =============================================================
    MQTTDisconnectPkt.m_pPayload = nullptr; // The DISCONNECT Packet has no payload.

    // =============================================================
    // Compute total packet size.
    // =============================================================
    MQTTDisconnectPkt.m_totalPacketSize = fxHeaderSize;
}

// -------------------------------------------------------------------------------------------------

void MQTT::getPacket(MQTTControlPacket& ctrlPkt, MQTTControlPacketDescriptor* pCtrlDescr)
{
    uint8_t* MQTTPacketBuffer = MQTT::getGlobalMQTTPacketBuffer();

    // Clear previous data stored in the control packet.
    ctrlPkt.m_fixedHeader.m_pData = MQTTPacketBuffer;
    ctrlPkt.m_variableHeader.m_pData = nullptr;
    ctrlPkt.m_pPayload = nullptr;
    ctrlPkt.m_totalPacketSize = 0;

    // Clear the packet descriptor's data if not null.
    if(pCtrlDescr != nullptr)
    {
        memset(pCtrlDescr, 0, sizeof(MQTTControlPacketDescriptor));
    }

    // =============================================================
    // Compute fixed header length.
    // =============================================================
    uint32_t remainingLength = *(reinterpret_cast<uint32_t*>(MQTTPacketBuffer + sizeof(uint8_t)));
    const uint8_t remainingLengthSize = MQTT::decodeRemainingLength(remainingLength);
    if(pCtrlDescr != nullptr)
    {
        pCtrlDescr->m_remainingLength = remainingLength;
    }

    // Fixed header length :
    //   * Packet type + flags (1 byte).
    //   * Reamining length (Max. 4 bytes).
    ctrlPkt.m_variableHeader.m_pData = MQTTPacketBuffer + 1 + remainingLengthSize;
    ctrlPkt.m_totalPacketSize += 1 + remainingLengthSize;
    if(pCtrlDescr != nullptr)
    {
        pCtrlDescr->m_fixedHeaderSize = 1 + remainingLengthSize;
    }

    // =============================================================
    // Compute variable header length + payload length.
    // =============================================================
    const MQTTControlPacketType ctrlPktType = static_cast<MQTTControlPacketType>(
        (*reinterpret_cast<const uint8_t*>(ctrlPkt.m_fixedHeader.m_pData) >> 4) & 0x0F);
    if(pCtrlDescr != nullptr)
    {
        pCtrlDescr->m_type = ctrlPktType;
    }

    switch(ctrlPktType)
    {
    case MQTTControlPacketType::CONNECT:
        ctrlPkt.m_pPayload = ctrlPkt.m_variableHeader.m_pData + 10;
        ctrlPkt.m_totalPacketSize += remainingLength; // Payload length.

        if(pCtrlDescr != nullptr)
        {
            pCtrlDescr->m_variableHeaderSize = 10;
            pCtrlDescr->m_payloadSize = (remainingLength - 10);
        }
        break;

    case MQTTControlPacketType::PUBLISH:
    {
        uint32_t varHeaderSize = sizeof(uint16_t) * 2;
        const uint16_t subjectLen = *reinterpret_cast<uint16_t*>(ctrlPkt.m_variableHeader.m_pData);

        varHeaderSize += MQTT::toLittleEndian(subjectLen);
        ctrlPkt.m_pPayload = ctrlPkt.m_variableHeader.m_pData + varHeaderSize;
        ctrlPkt.m_totalPacketSize += remainingLength; // Payload length.

        if(pCtrlDescr != nullptr)
        {
            pCtrlDescr->m_variableHeaderSize = varHeaderSize;
            pCtrlDescr->m_payloadSize = (remainingLength - varHeaderSize);
        }
    }
    break;

    case MQTTControlPacketType::SUBSCRIBE:
    case MQTTControlPacketType::SUBACK:
    case MQTTControlPacketType::UNSUBSCRIBE:
        ctrlPkt.m_pPayload = ctrlPkt.m_variableHeader.m_pData + 2;
        ctrlPkt.m_totalPacketSize += remainingLength; // Payload length.

        if(pCtrlDescr != nullptr)
        {
            pCtrlDescr->m_variableHeaderSize = 2;
            pCtrlDescr->m_payloadSize = (remainingLength - 2);
        }
        break;

    default:
        // This packet may have no variable header and surely no payload.
        ctrlPkt.m_totalPacketSize += remainingLength;

        if(pCtrlDescr != nullptr)
        {
            pCtrlDescr->m_variableHeaderSize = pCtrlDescr->m_remainingLength;
            pCtrlDescr->m_payloadSize = 0;
        }
    }

    if(pCtrlDescr != nullptr)
    {
        pCtrlDescr->m_totalPacketSize = ctrlPkt.m_totalPacketSize;
    }
}

// -------------------------------------------------------------------------------------------------

void MQTT::readPacket(const char* pInFilePath)
{
    FILE* pInput = fopen(pInFilePath, "rb");
    if(pInput == nullptr)
    {
        printf("Can't read from the specified file!\n");
        return;
    }

    uint8_t* MQTTPacketBuffer = MQTT::getGlobalMQTTPacketBuffer();
    fread(MQTTPacketBuffer, PACKET_MAX_LEN, 1, pInput);

    fclose(pInput);
}

// -------------------------------------------------------------------------------------------------

void MQTT::writePacket(const MQTTControlPacket& ctrlPkt, const char* pOutFilePath)
{
    FILE* pOutput = fopen(pOutFilePath, "wb");
    if(pOutput == nullptr)
    {
        printf("Can't write in the specified file!\n");
        return;
    }

    uint8_t* MQTTPacketBuffer = MQTT::getGlobalMQTTPacketBuffer();
    fwrite(MQTTPacketBuffer, ctrlPkt.m_totalPacketSize, 1, pOutput);

    fclose(pOutput);
}

} /* namespace Ocelot */

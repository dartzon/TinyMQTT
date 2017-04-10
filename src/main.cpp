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
 * \file      main.cpp
 *
 * \author    Othmane AIT EL CADI - dartzon@gmail.com
 * \date      29-01-2017
 */

#include <cstdlib>
#include <cstddef>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <type_traits>

// #ifndef MQTT_PROTOCOL_VERSION
// #   define MQTT_PROTOCOL_VERSION 0x04 // MQTT version 3.1.1.
// #endif

// constexpr uint16_t UTF8_STR_MAX_LEN = 65535;

// // 1 byte : Packet type + specific flags.
// // 4 bytes : Max for remaining length.
// constexpr uint8_t FIX_HEADER_MAX_LEN = 5;

// // Maximum variable header length formula:
// // A: Two byte length field.
// // B: Each topic level has max 8 characters.
// // C: We can have up to 4 levels.
// // D: Topic levels are separated by '/' -- (C - 1).
// // Total = A + (B * C) + (C - 1)
// // Total = 2 + (8 * 4) + 3 = 37
// constexpr uint8_t VAR_HEADER_MAX_LEN = 37;

// // Max packet length.
// constexpr uint8_t PACKET_MAX_LEN = FIX_HEADER_MAX_LEN + VAR_HEADER_MAX_LEN + 86;

#include "MQTTConfig.h"

uint8_t MQTTPacketBuffer[PACKET_MAX_LEN];

inline uint16_t toLittleEndian(const uint16_t BEData)
{
    const uint16_t LEData = BEData << 8 | BEData >> 8;

    return (LEData);
}

inline uint16_t toBigEndian(const uint16_t LEData)
{
    const uint16_t BEData = LEData << 8 | LEData >> 8;

    return (BEData);
}

uint8_t encodeRemainingLength(uint32_t& dataLength)
{
    uint8_t countBytes = 0;

    if(dataLength <= 127)
    {
        countBytes = 1;
    }
    else
        if(dataLength <= 16383)
        {
            countBytes = 2;

            uint32_t mod = (dataLength % 128) | 128;
            uint32_t div = (dataLength / 128) << 8;

            dataLength = div | mod;
        }
        else
            if(dataLength <= 2097151)
            {
                countBytes = 3;

                uint32_t mod = (dataLength % 128) | 128;
                uint32_t div = (dataLength / 128);

                mod |= ((div % 128) | 128) << 8;
                div = (div / 128) << 16;

                dataLength = div | mod;
            }
            else
            {
                countBytes = 4;

                uint32_t mod = (dataLength % 128) | 128;
                uint32_t div = (dataLength / 128);

                mod |= ((div % 128) | 128) << 8;
                div = (div / 128);

                mod |= ((div % 128) | 128) << 16;
                div = (div / 128) << 24;

                dataLength = div | mod;
            }

    return (countBytes);
}

uint8_t decodeRemainingLength(uint32_t& dataLength)
{
    uint8_t* pDataIter = reinterpret_cast<uint8_t*>(&dataLength);

    uint32_t val = 0;
    uint8_t shift = 0;

    uint8_t countBytes = 0;

    do
    {
        val += (*pDataIter & 127) << shift;
        shift+= 7;

        ++countBytes;
    }
    while((*pDataIter++ & 128) != 0);

    dataLength = val;

    return (countBytes);
}

// -------------------------------------------------------------------------------------------------

inline size_t storeUTF8String(uint8_t* pDestBuffer,
                              const char* pSrcStr, const size_t strLen)
{
    size_t srcStrSize = strLen;

    if(srcStrSize > UTF8_STR_MAX_LEN)
    {
        srcStrSize = UTF8_STR_MAX_LEN;
    }

    const uint16_t strSizeBE = toBigEndian(srcStrSize);
    memcpy(pDestBuffer, &strSizeBE, sizeof(uint16_t));

    if(srcStrSize > 0)
    {
        memcpy(pDestBuffer + sizeof(uint16_t), pSrcStr, srcStrSize);
    }

    return (sizeof(uint16_t) + srcStrSize);
}

template<typename NbrType> uint8_t storeNumber(uint8_t* pDestBuffer, const NbrType nbr)
{
    static_assert(std::is_integral<NbrType>::value, "Can only process integral values");

    memcpy(pDestBuffer, &nbr, sizeof(NbrType));

    return (sizeof(NbrType));
}

// -------------------------------------------------------------------------------------------------

// 1.5.3 UTF-8 encoded strings
struct UTF8String
{
    UTF8String(void)
    {
        m_pData[0] = 0;
        m_pData[1] = 0;
    }

    bool operator==(const char* pStr) const
    {
        const size_t strLength = strlen(pStr);

        if(strLength > UTF8_STR_MAX_LEN)
        {
            return (false);
        }

        if(*(reinterpret_cast<const uint16_t*>(m_pData)) == toBigEndian(strLength))
        {
            return (memcmp(m_pData + sizeof(uint16_t), pStr, UTF8_STR_MAX_LEN) == 0);
        }

        return (false);
    }

    bool operator==(const UTF8String& rStr) const
    {
        return (memcmp(m_pData, rStr.m_pData, sizeof(uint16_t) + UTF8_STR_MAX_LEN) == 0);
    }

    uint16_t getLength(void) const
    {
        return (toLittleEndian(*reinterpret_cast<const uint16_t*>(m_pData)));
    }

    uint8_t m_pData[sizeof(uint16_t) + UTF8_STR_MAX_LEN];  ///< String buffer.
};

uint32_t getUTF8String(const char* pSrcStr, const size_t strLen, UTF8String& destStr)
{
    size_t srcStrSize = strLen;

    if(srcStrSize > UTF8_STR_MAX_LEN)
    {
        srcStrSize = UTF8_STR_MAX_LEN;
    }

    const uint16_t strSizeBE = toBigEndian(srcStrSize);
    memcpy(destStr.m_pData, &strSizeBE, sizeof(uint16_t));

    if(srcStrSize > 0)
    {
        memcpy(destStr.m_pData + sizeof(uint16_t), pSrcStr, srcStrSize);
    }

    return (sizeof(uint16_t) + srcStrSize);
}

inline size_t storeUTF8String(uint8_t* pDestBuffer, const UTF8String& srcStr)
{
    const size_t memSize = sizeof(uint16_t) + srcStr.getLength();
    memcpy(pDestBuffer, srcStr.m_pData, memSize);

    return (memSize);
}

// -------------------------------------------------------------------------------------------------

enum class MQTTControlPacketType : uint8_t
{
    RESERVED_START = 0,  ///< Reserved. (Forbidden)
    CONNECT,             ///< Client request to connect to Server. (Client -> Server)
    CONNACK,             ///< Connect acknowledgment. (Server -> Client)
    PUBLISH,             ///< Publish message. (Client <-> Server)
    PUBACK,              ///< Publish acknowledgment. (Client <-> Server)
    PUBREC,              ///< Publish received (assured delivery part 1). (Client <-> Server)
    PUBREL,              ///< Publish release (assured delivery part 2). (Client <-> Server)
    PUBCOMP,             ///< Publish complete (assured delivery part 3). (Client <-> Server)
    SUBSCRIBE,           ///< Client subscribe request. (Client <-> Server)
    SUBACK,              ///< Subscribe acknowledgment. (Server -> Client)
    UNSUBSCRIBE,         ///< Unsubscribe request. (Client <-> Server)
    UNSUBACK,            ///< Unsubscribe acknowledgment. (Server -> Client)
    PINGREQ,             ///< PING request. (Client <-> Server)
    PINGRESP,            ///< PING response. (Server -> Client)
    DISCONNECT,          ///< Client is disconnecting. (Client <-> Server)
    RESERVED_END         ///< Reserved. (Forbidden)
};

enum class MQTTControlPacketFlag : uint8_t
{
    CONNECT_FLAG = 0x0,       ///< Reserved.
    CONNACK_FLAG = 0x0,       ///< Reserved.
    PUBLISH_FLAG,             ///< Used in MQTT 3.1.1 : DUP1 QoS QoS RETAIN
    PUBACK_FLAG = 0x0,        ///< Reserved.
    PUBREC_FLAG = 0x0,        ///< Reserved.
    PUBREL_FLAG = 0x2,        ///< Reserved.
    PUBCOMP_FLAG = 0x0,       ///< Reserved.
    SUBSCRIBE_FLAG = 0x2,     ///< Reserved.
    SUBACK_FLAG = 0x0,        ///< Reserved.
    UNSUBSCRIBE_FLAG = 0x2,   ///< Reserved.
    UNSUBACK_FLAG = 0x0,      ///< Reserved.
    PINGREQ_FLAG = 0x0,       ///< Reserved.
    PINGRESP_FLAG = 0x0,      ///< Reserved.
    DISCONNECT_FLAG = 0x0,    ///< Reserved.
};

enum class MQTTQoSLevel : uint8_t
{
    AT_MOST_ONE = 0,  ///< At most once delivery.
    AT_LEAST_ONE,     ///< At least once delivery.
    EXACTLY_ONE,      ///< Exactly once delivery.
    RESERVED,         ///< Reserved – must not be used.
    FAILURE = 0x80    ///< Server can't grant QoS level for client's subscription.
};

// 2.2 Fixed header
struct MQTTFixedHeader
{
    MQTTFixedHeader(void) :
        m_pData(nullptr)
    {
    }

    uint8_t* m_pData;  ///< Payload of the fixed header.
};

// 2.3 Variable header
struct MQTTVariableHeader
{
    MQTTVariableHeader(void) :
        m_pData(nullptr)
    {
    }

    uint8_t* m_pData;  ///< Payload of the variable header.
};

// 2.1 Structure of an MQTT Control Packet
struct MQTTControlPacket
{
    MQTTControlPacket(void) :
        m_pPayload(nullptr)
    {
    }

    MQTTFixedHeader m_fixedHeader;
    MQTTVariableHeader m_variableHeader;
    uint8_t* m_pPayload;

    uint32_t m_totalPacketSize;
};

// 3.2.2.3 Connect Return code
enum class MQTTConnectReturnCode : uint8_t
{
    CONNECTION_ACCEPTED = 0x0,  ///< Connection accepted.
    UNACCEPTABLE_PROTOCOL_VER,  ///< Unsupport MQTT protocol requested by the Client.
    IDENTIFIER_REJECTED,        ///< Client ID is correct but not allowed by the Server.
    SERVER_UNAVAILABLE = 0x0,   ///< Connection established but MQTT service is unavailable.
    BAD_USERNAME_OR_PWD = 0x0,  ///< Malformed data in the user name or the password.
    NOT_AUTHORIZED = 0x2        ///< Client not authorized to connect.
};

// -------------------------------------------------------------------------------------------------

struct MQTTControlPacketDescriptor
{
    uint32_t m_fixedHeaderSize;
    uint32_t m_remainingLength;
    uint32_t m_variableHeaderSize;
    uint32_t m_payloadSize;
    uint32_t m_totalPacketSize;
    MQTTControlPacketType m_type;
};

void describeControlPacket(const MQTTControlPacket& ctrlPkt, MQTTControlPacketDescriptor& ctrlDescr)
{
    // =============================================================
    // Compute fixed header length.
    // =============================================================
    uint32_t remainingLength = *(reinterpret_cast<uint32_t*>(ctrlPkt.m_fixedHeader.m_pData +
                                                             sizeof(uint8_t)));
    const uint8_t remainingLengthSize = decodeRemainingLength(remainingLength);

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
        varHeaderSize += toLittleEndian(subjectLen);

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

inline uint8_t createFixedHeader(MQTTFixedHeader& MQTTFxHeader,
                                 const MQTTControlPacketType ctrlPktType,
                                 uint32_t remainingLength, const uint8_t lowerQuadbit = 0)
{
    MQTTFxHeader.m_pData = MQTTPacketBuffer;
    MQTTFxHeader.m_pData[0] = static_cast<uint8_t>(ctrlPktType) << 4 | lowerQuadbit;
    const uint8_t remainingLengthInBytes = encodeRemainingLength(remainingLength);
    memcpy(MQTTFxHeader.m_pData + 1, &remainingLength, remainingLengthInBytes);

    return (1 + remainingLengthInBytes);
}

// -------------------------------------------------------------------------------------------------

// 3.1 CONNECT – Client requests a connection to a Server.
void createConnectPacket(MQTTControlPacket& MQTTConnectPkt,
                         const bool cleanSession, const bool willFlag, const MQTTQoSLevel QoSLvl,
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
    *(reinterpret_cast<uint16_t*>(pVarHeaderData + 8)) = toBigEndian(keepAliveSec);

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

// 3.2 CONNACK – Acknowledge connection request.
void createConnAckPacket(MQTTControlPacket& MQTTConnectAckPkt,
                         const bool sessionPresent, const MQTTConnectReturnCode retCode)
{
    // =============================================================
    // Create the FIXED header.
    // =============================================================
    MQTTFixedHeader& MQTTFxHeader = MQTTConnectAckPkt.m_fixedHeader;
    const uint8_t fxHeaderSize = createFixedHeader(MQTTFxHeader, MQTTControlPacketType::CONNACK, 2);

    // =============================================================++
    // Create the VARIABLE header.
    // =============================================================
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

// 3.3 PUBLISH – Publish message.
void createPublishPacket(MQTTControlPacket& MQTTPubPkt,
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
    uint8_t* pVarHeaderData = MQTTPacketBuffer + fxHeaderSize;
    const uint32_t bytesShift = storeUTF8String(pVarHeaderData, pTopicNameTxt, topicNameLength);

    // Create the client identifier.
    if(packetID > 0)
    {
        *(reinterpret_cast<uint16_t*>(pVarHeaderData + bytesShift)) = toBigEndian(packetID);
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

// 3.4 PUBACK – Publish acknowledgement.
void createPubAckPacket(MQTTControlPacket& MQTTPubAckPkt,
                        const uint16_t packetID)
{
    // =============================================================
    // Create the FIXED header.
    // =============================================================
    MQTTFixedHeader& MQTTFxHeader = MQTTPubAckPkt.m_fixedHeader;
    const uint8_t fxHeaderSize = createFixedHeader(MQTTFxHeader, MQTTControlPacketType::PUBACK, 2);

    // =============================================================
    // Create the VARIABLE header.
    // =============================================================
    uint8_t* pVarHeaderData = MQTTPacketBuffer + fxHeaderSize;
    *(reinterpret_cast<uint16_t*>(pVarHeaderData)) = toBigEndian(packetID);

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

// 3.5 PUBREC – Publish received (QoS 2 publish received, part 1).
void createPubRecPacket(MQTTControlPacket& MQTTPubRecPkt,
                        const uint16_t packetID)
{
    // =============================================================
    // Create the FIXED header.
    // =============================================================
    MQTTFixedHeader& MQTTFxHeader = MQTTPubRecPkt.m_fixedHeader;
    const uint8_t fxHeaderSize = createFixedHeader(MQTTFxHeader, MQTTControlPacketType::PUBREC, 2);

    // =============================================================
    // Create the VARIABLE header.
    // =============================================================
    uint8_t* pVarHeaderData = MQTTPacketBuffer + fxHeaderSize;
    *(reinterpret_cast<uint16_t*>(pVarHeaderData)) = toBigEndian(packetID);

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

// 3.6 PUBREL – Publish release (QoS 2 publish received, part 2).
void createPubRelPacket(MQTTControlPacket& MQTTPubRelPkt,
                        const uint16_t packetID)
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
    uint8_t* pVarHeaderData = MQTTPacketBuffer + fxHeaderSize;
    *(reinterpret_cast<uint16_t*>(pVarHeaderData)) = toBigEndian(packetID);

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

// 3.7 PUBCOMP – Publish complete (QoS 2 publish received, part 3).
void createPubCompPacket(MQTTControlPacket& MQTTPubCompPkt,
                         const uint16_t packetID)
{
    // =============================================================
    // Create the FIXED header.
    // =============================================================
    MQTTFixedHeader& MQTTFxHeader = MQTTPubCompPkt.m_fixedHeader;
    const uint8_t fxHeaderSize = createFixedHeader(MQTTFxHeader, MQTTControlPacketType::PUBCOMP, 2);

    // =============================================================
    // Create the VARIABLE header.
    // =============================================================
    uint8_t* pVarHeaderData = MQTTPacketBuffer + fxHeaderSize;
    *(reinterpret_cast<uint16_t*>(pVarHeaderData)) = toBigEndian(packetID);

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

// 3.8 SUBSCRIBE - Subscribe to topics.
void createSubscribePacket(MQTTControlPacket& MQTTSubscribePkt,
                           const uint16_t packetID,
                           const char** ppTopicFiltersTxt, const uint16_t* pTopicFiltersLengths,
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
    uint8_t* pVarHeaderData = MQTTPacketBuffer + fxHeaderSize;
    *(reinterpret_cast<uint16_t*>(pVarHeaderData)) = toBigEndian(packetID);

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
        bytesShift += storeNumber(pPayloadData + bytesShift,
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
void createSubAckPacket(MQTTControlPacket& MQTTSubAckPkt,
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
    uint8_t* pVarHeaderData = MQTTPacketBuffer + fxHeaderSize;
    *(reinterpret_cast<uint16_t*>(pVarHeaderData)) = toBigEndian(packetID);

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

// 3.10 UNSUBSCRIBE – Unsubscribe from topics.
void createUnsubscribePacket(MQTTControlPacket& MQTTUnsubscribePkt,
                             const uint16_t packetID,
                             const char** ppTopicFiltersTxt, const uint16_t* pTopicFiltersLengths,
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
    uint8_t* pVarHeaderData = MQTTPacketBuffer + fxHeaderSize;
    *(reinterpret_cast<uint16_t*>(pVarHeaderData)) = toBigEndian(packetID);

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

// 3.11 UNSUBACK – Unsubscribe acknowledgement.
void createUnsubAckPacket(MQTTControlPacket& MQTTUnSubAckPkt,
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
    uint8_t* pVarHeaderData = MQTTPacketBuffer + fxHeaderSize;
    *(reinterpret_cast<uint16_t*>(pVarHeaderData)) = toBigEndian(packetID);

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

// 3.12 PINGREQ – PING request.
void createPingReqPacket(MQTTControlPacket& MQTTPingReqPkt)
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

// 3.13 PINGRESP – PING response.
void createPingRespPacket(MQTTControlPacket& MQTTPingRespPkt)
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

// 3.14 DISCONNECT – Disconnect notification.
void createDisconnectPacket(MQTTControlPacket& MQTTDisconnectPkt)
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

void getPacket(MQTTControlPacket& ctrlPkt, MQTTControlPacketDescriptor* pCtrlDescr = nullptr)
{
    // Clear previous data stored in the control packet.
    ctrlPkt.m_fixedHeader.m_pData = MQTTPacketBuffer;
    ctrlPkt.m_variableHeader.m_pData = nullptr;
    ctrlPkt.m_pPayload = nullptr;
    ctrlPkt.m_totalPacketSize = 0;

    // =============================================================
    // Compute fixed header length.
    // =============================================================
    uint32_t remainingLength = *(reinterpret_cast<uint32_t*>(MQTTPacketBuffer + sizeof(uint8_t)));
    const uint8_t remainingLengthSize = decodeRemainingLength(remainingLength);
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
        ctrlPkt.m_totalPacketSize += 10; // Variable header length.
        ctrlPkt.m_totalPacketSize += (remainingLength - 10); // Payload length.

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

        varHeaderSize += toLittleEndian(subjectLen);
        ctrlPkt.m_pPayload = ctrlPkt.m_variableHeader.m_pData + varHeaderSize;
        ctrlPkt.m_totalPacketSize += varHeaderSize; // Variable header length.
        ctrlPkt.m_totalPacketSize += (remainingLength - varHeaderSize); // Payload length.

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
        ctrlPkt.m_totalPacketSize += 2; // Variable header length.
        ctrlPkt.m_totalPacketSize += (remainingLength - 2); // Payload length.

        if(pCtrlDescr != nullptr)
        {
            pCtrlDescr->m_variableHeaderSize = 2;
            pCtrlDescr->m_payloadSize = (remainingLength - 2);
        }
        break;

    default: break;
    }

    if(pCtrlDescr != nullptr)
    {
        pCtrlDescr->m_totalPacketSize = ctrlPkt.m_totalPacketSize;
    }
}

// -------------------------------------------------------------------------------------------------

void readPacket(const char* pInFilePath)
{
    FILE* pInput = fopen(pInFilePath, "rb");
    if(pInput == nullptr)
    {
        printf("Can't read from the specified file!\n");
        return;
    }

    fread(MQTTPacketBuffer, PACKET_MAX_LEN, 1, pInput);

    fclose(pInput);
}

void writePacket(const MQTTControlPacket& ctrlPkt, const char* pOutFilePath)
{
    FILE* pOutput = fopen(pOutFilePath, "wb");
    if(pOutput == nullptr)
    {
        printf("Can't write in the specified file!\n");
        return;
    }

    fwrite(MQTTPacketBuffer, ctrlPkt.m_totalPacketSize, 1, pOutput);

    fclose(pOutput);
}

// -------------------------------------------------------------------------------------------------

int main(void)
{
    MQTTControlPacket MQTTPkt;

    createConnectPacket(MQTTPkt, true, true, MQTTQoSLevel::AT_LEAST_ONE, false, true, true,
                        10, "ShadowMoses", 11, "TPK", 3, "WILLMSG", 7,
                        "dartzon", 7, "1234", 4);
    writePacket(MQTTPkt, "packets-saves/MQTT-ConnectPacket.txt");

    createConnAckPacket(MQTTPkt, true, MQTTConnectReturnCode::CONNECTION_ACCEPTED);
    writePacket(MQTTPkt, "packets-saves/MQTT-ConnectAckPacket.txt");

    const char* buff = "Hello!";
    createPublishPacket(MQTTPkt, true, MQTTQoSLevel::AT_LEAST_ONE, true,
                        "living_room", 11, 1989, (const uint8_t*)buff, 6);
    writePacket(MQTTPkt, "packets-saves/MQTT-PublishPacket.txt");

    createPubAckPacket(MQTTPkt, 1989);
    writePacket(MQTTPkt, "packets-saves/MQTT-PubAckPacket.txt");

    createPubRecPacket(MQTTPkt, 1989);
    writePacket(MQTTPkt, "packets-saves/MQTT-PubRecPacket.txt");

    createPubRelPacket(MQTTPkt, 1989);
    writePacket(MQTTPkt, "packets-saves/MQTT-PubRelPacket.txt");

    createPubCompPacket(MQTTPkt, 1989);
    writePacket(MQTTPkt, "packets-saves/MQTT-PubCompPacket.txt");

    const char* topicFilters[] = {"a/b/c", "x/y/z", "r/g/b"};
    const uint16_t topicFiltersLength[] = {5, 5, 5};
    const MQTTQoSLevel requestedQoSs[] = {MQTTQoSLevel::AT_LEAST_ONE,
                                          MQTTQoSLevel::AT_MOST_ONE,
                                          MQTTQoSLevel::EXACTLY_ONE};
    createSubscribePacket(MQTTPkt, 1989, topicFilters, topicFiltersLength,
                          requestedQoSs, 3);
    writePacket(MQTTPkt, "packets-saves/MQTT-SubscribePacket.txt");

    const MQTTQoSLevel returnedQoSs[] = {MQTTQoSLevel::AT_LEAST_ONE,
                                         MQTTQoSLevel::AT_MOST_ONE,
                                         MQTTQoSLevel::EXACTLY_ONE};
    createSubAckPacket(MQTTPkt, 1989, returnedQoSs, 3);
    writePacket(MQTTPkt, "packets-saves/MQTT-SubAckPacket.txt");

    createUnsubscribePacket(MQTTPkt, 1989, topicFilters, topicFiltersLength, 3);
    writePacket(MQTTPkt, "packets-saves/MQTT-UnsubscribePacket.txt");

    createUnsubAckPacket(MQTTPkt, 1989);
    writePacket(MQTTPkt, "packets-saves/MQTT-UnsubAckPacket.txt");

    createPingReqPacket(MQTTPkt);
    writePacket(MQTTPkt, "packets-saves/MQTT-PingReqPacket.txt");

    createPingRespPacket(MQTTPkt);
    writePacket(MQTTPkt,"packets-saves/MQTT-PingRespPacket.txt");

    createDisconnectPacket(MQTTPkt);
    writePacket(MQTTPkt,"packets-saves/MQTT-DisconnectPacket.txt");

    return (1);
}

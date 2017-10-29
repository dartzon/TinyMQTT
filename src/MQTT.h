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
 * \file      MQTT.h
 *
 * \brief     <brief description>
 * \details   <detailed description>
 *
 * \author    Othmane AIT EL CADI - dartzon@gmail.com
 * \date      28-05-2017
 */

#ifndef __MQTT_H__
#define __MQTT_H__

#include "MQTTConfig.h"

namespace Ocelot
{
namespace MQTT
{

// 2.2.1 MQTT Control Packet type.
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

// 2.2.2 Flags.
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

// 3.3.1.2 QoS (Table 3.2 - QoS definitions).
enum class MQTTQoSLevel : uint8_t
{
    AT_MOST_ONE = 0,  ///< At most once delivery.
    AT_LEAST_ONE,     ///< At least once delivery.
    EXACTLY_ONE,      ///< Exactly once delivery.
    RESERVED,         ///< Reserved – must not be used.
    FAILURE = 0x80    ///< Server can't grant QoS level for client's subscription.
};

// 3.2.2.3 Connect Return code.
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

// 2.2 Fixed header.
struct MQTTFixedHeader
{
    MQTTFixedHeader(void) :
        m_pData(nullptr)
    {
    }

    uint8_t* m_pData;  ///< Payload of the fixed header.
};

// 2.3 Variable header.
struct MQTTVariableHeader
{
    MQTTVariableHeader(void) :
        m_pData(nullptr)
    {
    }

    uint8_t* m_pData;  ///< Payload of the variable header.
};

// 2.1 Structure of an MQTT Control Packet.
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

void describeControlPacket(const MQTTControlPacket& ctrlPkt,
                           MQTTControlPacketDescriptor& ctrlDescr);

void debugPrintControlPacket(MQTTControlPacketDescriptor& ctrlDescr);

// -------------------------------------------------------------------------------------------------

uint8_t createFixedHeader(MQTTFixedHeader& MQTTFxHeader, const MQTTControlPacketType ctrlPktType,
                          uint32_t remainingLength, const uint8_t lowerQuadbit = 0);

// -------------------------------------------------------------------------------------------------

// 3.1 CONNECT – Client requests a connection to a Server.
void createConnectPacket(MQTTControlPacket& MQTTConnectPkt,
                         const bool cleanSession, const bool willFlag, const MQTTQoSLevel QoSLvl,
                         const bool willRetain, const bool pwdFlag, const bool usernameFlag,
                         const uint16_t keepAliveSec,
                         const char* pClientIDTxt, const std::size_t clientIDLength,
                         const char* pWillTopicTxt, const std::size_t willTopicLength,
                         const char* pWillMsgTxt, const std::size_t willMsgLength,
                         const char* pUsernameTxt, const std::size_t usernameLength,
                         const char* pPasswordTxt, const std::size_t passwordLength);

// -------------------------------------------------------------------------------------------------

// 3.2 CONNACK – Acknowledge connection request.
void createConnAckPacket(MQTTControlPacket& MQTTConnectAckPkt,
                         const bool sessionPresent, const MQTTConnectReturnCode retCode);

// -------------------------------------------------------------------------------------------------

// 3.3 PUBLISH – Publish message.
void createPublishPacket(MQTTControlPacket& MQTTPubPkt,
                         const bool DUPFlag, const MQTTQoSLevel QoSLvl, const bool retainFlag,
                         const char* pTopicNameTxt, const std::size_t topicNameLength,
                         const uint16_t packetID,
                         const uint8_t* pPayloadData, const uint32_t payloadSize);

// -------------------------------------------------------------------------------------------------

// 3.4 PUBACK – Publish acknowledgement.
void createPubAckPacket(MQTTControlPacket& MQTTPubAckPkt, const uint16_t packetID);

// -------------------------------------------------------------------------------------------------

// 3.5 PUBREC – Publish received (QoS 2 publish received, part 1).
void createPubRecPacket(MQTTControlPacket& MQTTPubRecPkt, const uint16_t packetID);

// -------------------------------------------------------------------------------------------------

// 3.6 PUBREL – Publish release (QoS 2 publish received, part 2).
void createPubRelPacket(MQTTControlPacket& MQTTPubRelPkt, const uint16_t packetID);

// -------------------------------------------------------------------------------------------------

// 3.7 PUBCOMP – Publish complete (QoS 2 publish received, part 3).
void createPubCompPacket(MQTTControlPacket& MQTTPubCompPkt, const uint16_t packetID);

// -------------------------------------------------------------------------------------------------

// 3.8 SUBSCRIBE - Subscribe to topics.
void createSubscribePacket(MQTTControlPacket& MQTTSubscribePkt,
                           const uint16_t packetID,
                           const char** ppTopicFiltersTxt, const uint16_t* pTopicFiltersLengths,
                           const MQTTQoSLevel* pRequestedQoSs,
                           const uint32_t countTopicFilters);

// -------------------------------------------------------------------------------------------------

// 3.9 SUBACK – Subscribe acknowledgement.
void createSubAckPacket(MQTTControlPacket& MQTTSubAckPkt,
                        const uint16_t packetID,
                        const MQTTQoSLevel* pReturnCodes, const uint32_t countReturnCodes);

// -------------------------------------------------------------------------------------------------

// 3.10 UNSUBSCRIBE – Unsubscribe from topics.
void createUnsubscribePacket(MQTTControlPacket& MQTTUnsubscribePkt,
                             const uint16_t packetID,
                             const char** ppTopicFiltersTxt, const uint16_t* pTopicFiltersLengths,
                             const uint32_t countTopicFilters);

// -------------------------------------------------------------------------------------------------

// 3.11 UNSUBACK – Unsubscribe acknowledgement.
void createUnsubAckPacket(MQTTControlPacket& MQTTUnSubAckPkt, const uint16_t packetID);

// -------------------------------------------------------------------------------------------------

// 3.12 PINGREQ – PING request.
void createPingReqPacket(MQTTControlPacket& MQTTPingReqPkt);

// -------------------------------------------------------------------------------------------------

// 3.13 PINGRESP – PING response.
void createPingRespPacket(MQTTControlPacket& MQTTPingRespPkt);

// -------------------------------------------------------------------------------------------------

// 3.14 DISCONNECT – Disconnect notification.
void createDisconnectPacket(MQTTControlPacket& MQTTDisconnectPkt);

// -------------------------------------------------------------------------------------------------

inline uint8_t* getGlobalMQTTPacketBuffer(void)
{
    static uint8_t gMQTTPacketBuffer[PACKET_MAX_LEN];

    return (gMQTTPacketBuffer);
}

// -------------------------------------------------------------------------------------------------

void getPacket(MQTTControlPacket& ctrlPkt, MQTTControlPacketDescriptor* pCtrlDescr = nullptr);

// -------------------------------------------------------------------------------------------------

void readPacket(const char* pInFilePath);

// -------------------------------------------------------------------------------------------------

void writePacket(const MQTTControlPacket& ctrlPkt, const char* pOutFilePath);

} /* namespace MQTT */
} /* namespace Ocelot */

#endif /* __MQTT_H__ */

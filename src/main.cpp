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

#include "MQTTConfig.h"
#include "MQTTNumeric.h"
#include "MQTTString.h"
#include "MQTTStringUtils.h"
#include "MQTT.h"

#include <asio.hpp>

using namespace Ocelot;
using namespace MQTT;

int main(void)
{
    MQTTControlPacket MQTTPkt;

    createConnectPacket(MQTTPkt, true, true, MQTTQoSLevel::AT_LEAST_ONE, false, true, true,
                        10, "ShadowMoses", 11, "TPK", 3, "WILLMSG", 7,
                        "dartzon", 7, "1234", 4);
    // writePacket(MQTTPkt, "packets-saves/MQTT-ConnectPacket.txt");

    // createConnAckPacket(MQTTPkt, true, MQTTConnectReturnCode::CONNECTION_ACCEPTED);
    // writePacket(MQTTPkt, "packets-saves/MQTT-ConnectAckPacket.txt");

    // const char* buff = "Hello!";
    // createPublishPacket(MQTTPkt, true, MQTTQoSLevel::AT_LEAST_ONE, true,
    //                     "living_room", 11, 1989, (const uint8_t*)buff, 6);
    // writePacket(MQTTPkt, "packets-saves/MQTT-PublishPacket.txt");

    // createPubAckPacket(MQTTPkt, 1989);
    // writePacket(MQTTPkt, "packets-saves/MQTT-PubAckPacket.txt");

    // createPubRecPacket(MQTTPkt, 1989);
    // writePacket(MQTTPkt, "packets-saves/MQTT-PubRecPacket.txt");

    // createPubRelPacket(MQTTPkt, 1989);
    // writePacket(MQTTPkt, "packets-saves/MQTT-PubRelPacket.txt");

    // createPubCompPacket(MQTTPkt, 1989);
    // writePacket(MQTTPkt, "packets-saves/MQTT-PubCompPacket.txt");

    // const char* topicFilters[] = {"a/b/c", "x/y/z", "r/g/b"};
    // const uint16_t topicFiltersLength[] = {5, 5, 5};
    // const MQTTQoSLevel requestedQoSs[] = {MQTTQoSLevel::AT_LEAST_ONE,
    //                                       MQTTQoSLevel::AT_MOST_ONE,
    //                                       MQTTQoSLevel::EXACTLY_ONE};
    // createSubscribePacket(MQTTPkt, 1989, topicFilters, topicFiltersLength,
    //                       requestedQoSs, 3);
    // writePacket(MQTTPkt, "packets-saves/MQTT-SubscribePacket.txt");

    // const MQTTQoSLevel returnedQoSs[] = {MQTTQoSLevel::AT_LEAST_ONE,
    //                                      MQTTQoSLevel::AT_MOST_ONE,
    //                                      MQTTQoSLevel::EXACTLY_ONE};
    // createSubAckPacket(MQTTPkt, 1989, returnedQoSs, 3);
    // writePacket(MQTTPkt, "packets-saves/MQTT-SubAckPacket.txt");

    // createUnsubscribePacket(MQTTPkt, 1989, topicFilters, topicFiltersLength, 3);
    // writePacket(MQTTPkt, "packets-saves/MQTT-UnsubscribePacket.txt");

    // createUnsubAckPacket(MQTTPkt, 1989);
    // writePacket(MQTTPkt, "packets-saves/MQTT-UnsubAckPacket.txt");

    // createPingReqPacket(MQTTPkt);
    // writePacket(MQTTPkt, "packets-saves/MQTT-PingReqPacket.txt");

    // createPingRespPacket(MQTTPkt);
    // writePacket(MQTTPkt,"packets-saves/MQTT-PingRespPacket.txt");

    // createDisconnectPacket(MQTTPkt);
    // writePacket(MQTTPkt,"packets-saves/MQTT-DisconnectPacket.txt");

    std::string ipAddrStr = "192.168.1.108";
    const uint16_t portNum = 1883;

    asio::error_code err;
    asio::ip::address clientIP = asio::ip::address::from_string(ipAddrStr, err);

    if(err.value() != 0)
    {
        printf("Invalid IP address\n");
        return (err.value());
    }

    asio::ip::tcp::endpoint clientEnd(clientIP, portNum);

    // *********************************************************

    asio::ip::address serverIP = asio::ip::address_v4::any();
    asio::ip::tcp::endpoint serverEnd(serverIP, portNum);



    return (1);
}

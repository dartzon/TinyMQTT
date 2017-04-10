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
 * \file      MQTTConfig.h
 *
 * \brief     <brief description>
 * \details   <detailed description>
 *
 * \author    Othmane AIT EL CADI - dartzon@merylaptop
 * \date      27-03-2017
 */

#ifndef __MQTTCONFIG_H__
#define __MQTTCONFIG_H__

#ifndef MQTT_PROTOCOL_VERSION
#   define MQTT_PROTOCOL_VERSION 0x04 // MQTT version 3.1.1.
#endif

constexpr uint16_t UTF8_STR_MAX_LEN = 65535;

// 1 byte : Packet type + specific flags.
// 4 bytes : Max for remaining length.
constexpr uint8_t FIX_HEADER_MAX_LEN = 5;

// Maximum variable header length formula:
// A: Two byte length field.
// B: Each topic level has max 8 characters.
// C: We can have up to 4 levels.
// D: Topic levels are separated by '/' -- (C - 1).
// Total = A + (B * C) + (C - 1)
// Total = 2 + (8 * 4) + 3 = 37
constexpr uint8_t VAR_HEADER_MAX_LEN = 37;

// Max packet length.
constexpr uint8_t PACKET_MAX_LEN = FIX_HEADER_MAX_LEN + VAR_HEADER_MAX_LEN + 86;

#endif /* __MQTTCONFIG_H__ */

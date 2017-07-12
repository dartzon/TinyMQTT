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
 * \file      MQTTNumeric.h
 *
 * \brief     Numeric functions.
 * \details   Functions used for numeric endianess conversion
 *            and encoding according to MQTT needs.
 *
 * \author    Othmane AIT EL CADI - dartzon@gmail.com
 * \date      12-04-2017
 */

#ifndef __MQTTNUMERIC_H__
#define __MQTTNUMERIC_H__

// STD includes.
#include <cstdint>
#include <type_traits>
#include <cstring>

namespace Ocelot
{
namespace MQTT
{

uint16_t toLittleEndian(const uint16_t BEData);

uint16_t toBigEndian(const uint16_t LEData);

uint8_t encodeRemainingLength(uint32_t& dataLength);

uint8_t decodeRemainingLength(uint32_t& dataLength);

template<typename NbrType> uint8_t storeNumber(uint8_t* pDestBuffer, const NbrType nbr)
{
    static_assert(std::is_integral<NbrType>::value, "Can only process integral values");

    memcpy(pDestBuffer, &nbr, sizeof(NbrType));

    return (sizeof(NbrType));
}

} /* namespace Ocelot */
} /* namespace MQTT  */

#endif /* __MQTTNUMERIC_H__ */

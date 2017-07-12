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
 * \file      MQTTString.cpp
 *
 * \author    Othmane AIT EL CADI - dartzon@gmail.com
 * \date      11-04-2017
 */

#include "MQTTString.h"
#include "MQTTNumeric.h"

#include <cstring>

namespace Ocelot
{

bool MQTT::UTF8String::operator==(const char* pStr) const
{
    const size_t strLength = strlen(pStr);

    if(strLength > UTF8_STR_MAX_LEN)
    {
        return (false);
    }

    if(*(reinterpret_cast<const uint16_t*>(m_pData)) == MQTT::toBigEndian(strLength))
    {
        return (memcmp(m_pData + sizeof(uint16_t), pStr, UTF8_STR_MAX_LEN) == 0);
    }

    return (false);
}

/* ============================================================================================== */

bool MQTT::UTF8String::operator==(const UTF8String& rStr) const
{
    return (memcmp(m_pData, rStr.m_pData, sizeof(uint16_t) + UTF8_STR_MAX_LEN) == 0);
}

/* ============================================================================================== */

uint16_t MQTT::UTF8String::getLength(void) const
{
    return (MQTT::toLittleEndian(*reinterpret_cast<const uint16_t*>(m_pData)));
}

} /* namespace Ocelot */

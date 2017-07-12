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
 * \file      MQTTNumeric.cpp
 *
 * \author    Othmane AIT EL CADI - dartzon@gmail.com
 * \date      12-04-2017
 */

// Local includes.
#include "MQTTNumeric.h"

namespace Ocelot
{

uint16_t MQTT::toLittleEndian(const uint16_t BEData)
{
    const uint16_t LEData = BEData << 8 | BEData >> 8;

    return (LEData);
}

/* ============================================================================================== */

uint16_t MQTT::toBigEndian(const uint16_t LEData)
{
    const uint16_t BEData = LEData << 8 | LEData >> 8;

    return (BEData);
}

/* ============================================================================================== */

uint8_t MQTT::encodeRemainingLength(uint32_t& dataLength)
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

/* ============================================================================================== */

uint8_t MQTT::decodeRemainingLength(uint32_t& dataLength)
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

}

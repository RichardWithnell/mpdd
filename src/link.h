/*
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    Author: Richard Withnell
    github.com/richardwithnell
 */

#ifndef MPD_NETWORK
#define MPD_NETWORK

/*Link Types*/
#define LINK_TYPE_ETH 0x00
#define LINK_TYPE_WLAN 0x01
#define LINK_TYPE_CELLULAR 0x02
#define LINK_TYPE_SATELLITE 0x03
#define LINK_TYPE_WIMAX 0x04

/*Ethernet Technologies*/
#define LINK_CAT_ETH_TEN 0x00
#define LINK_CAT_ETH_FAST 0x01
#define LINK_CAT_ETH_GIGABIT 0x02
#define LINK_CAT_ETH_TEN_GIGABIT 0x03

/*WLAN Technologies*/
#define LINK_CAT_WLAN_80211A 0x00
#define LINK_CAT_WLAN_80211B 0x01
#define LINK_CAT_WLAN_80211G 0x02
#define LINK_CAT_WLAN_80211N 0x03
#define LINK_CAT_WLAN_80211AC 0x04

/*Cellular Technologies*/
#define LINK_CAT_CELLULAR_CSD 0x00
#define LINK_CAT_CELLULAR_GPRS 0x01
#define LINK_CAT_CELLULAR_EDGE 0x02
#define LINK_CAT_CELLULAR_EEDGE 0x03
#define LINK_CAT_CELLULAR_UMTS 0x04
#define LINK_CAT_CELLULAR_HSPA 0x05
#define LINK_CAT_CELLULAR_HSDPA 0x06
#define LINK_CAT_CELLULAR_HSUPA 0x07

/*Satellite Technologies*/
#define LINK_CAT_SATELLITE_DEF 0x00

/*WiMax Technologies*/
#define LINK_CAT_WIMAX_DEF 0x00

#define LINK_TECHNOLOGY(maj,min)    ((maj) << 8 | (min))

#endif

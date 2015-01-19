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

/*
 * version.h	Versioning Information
 */

#ifndef MPDD_VERSION_H_
#define MPDD_VERSION_H_

/* Compile Time Versioning Information */

#define MPDD_STRING "mpdd 0.1.0"
#define MPDD_VERSION "0.1.0"

#define MPDD_VER_MAJ        0
#define MPDD_VER_MIN        1
#define MPDD_VER_MIC        0
#define MPDD_VER(maj,min)   ((maj) << 8 | (min))
#define MPDD_VER_NUM        MPDD_VER(MPDD_VER_MAJ, MPDD_VER_MIN)

#define MPDD_CURRENT        1
#define MPDD_REVISION       0
#define MPDD_AGE        0

/* Run-time version information */

extern const int mpdd_ver_num;
extern const int mpdd_ver_maj;
extern const int mpdd_ver_min;
extern const int mpdd_ver_mic;

#endif

/* end file: util.h */

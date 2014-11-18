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

#ifndef __DEBUG_H__
#define __DEBUG_H__

#define DEBUG
#define ERROR
#define VERBOSE

#include <stdio.h>

#ifdef DEBUG
#define DO_DEBUG 1
#else
#define DO_DEBUG 0
#endif

#ifdef ERROR
#define DO_ERROR 1
#else
#define DO_ERROR 0
#endif

#ifdef VERBOSE
#define DO_VERB 1
#else
#define DO_VERB 0
#endif

#define print_error(fmt, ...) \
        do { if(DO_ERROR) fprintf(stderr, "ERROR:%s:%d:%s(): " fmt, __FILE__, \
                                __LINE__, __func__, ## __VA_ARGS__); } while (0)

#define print_debug(fmt, ...) \
        do { if(DO_DEBUG) fprintf(stderr, "DEBUG:%s:%d:%s(): " fmt, __FILE__, \
                                __LINE__, __func__, ## __VA_ARGS__); } while (0)

#define print_verb(fmt, ...) \
        do { if(DO_VERB) fprintf(stderr,  "VERB :%s:%d:%s(): " fmt, __FILE__, \
                                __LINE__, __func__, ## __VA_ARGS__); } while (0)

#endif

/* end file: debug.h */

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

#include <stdio.h>
#include <time.h>

#define DEBUG
#define ERROR
#define VERBOSE
#define LOG
#define EVAL

#ifdef EVAL
#define DO_EVAL 1
#else
#define DO_EVAL 0
#endif

#ifdef LOG
#define DO_LOG 1
#else
#define DO_LOG 0
#endif

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

#ifdef DCE_NS3_FIX

#include <time.h>

#define print_eval(fmt, ...) \
    do { if(DO_EVAL) {fprintf(stdout,  "EVAL:" fmt, \
                              ## __VA_ARGS__); } } while (0);

#define print_log(fmt, ...) \
    do { \
        struct timespec monotime; \
        clock_gettime(CLOCK_MONOTONIC, &monotime); \
        if(DO_LOG) { \
            fprintf(stdout,  "LOG:%s:%d:%s():%lld: " \
                    fmt, __FILE__, __LINE__, __func__, \
                    (long long)monotime.tv_sec, \
                    ## __VA_ARGS__); } \
    } while (0)

#define print_error(fmt, ...) \
    do { \
        struct timespec monotime; \
        clock_gettime(CLOCK_MONOTONIC, &monotime); \
        if(DO_ERROR) { \
            fprintf(stderr, "ERROR:%s:%d:%s():%lld: " \
                    fmt, __FILE__, __LINE__, __func__, \
                    (long long)monotime.tv_sec, \
                    ## __VA_ARGS__); } \
    } while (0)

#define print_debug(fmt, ...) \
    do { \
        struct timespec monotime; \
        clock_gettime(CLOCK_MONOTONIC, &monotime); \
        if(DO_DEBUG) { \
            fprintf(stdout, "DEBUG:%s:%d:%s():%lld:  " \
                    fmt, __FILE__, __LINE__, __func__, \
                    (long long)monotime.tv_sec, \
                    ## __VA_ARGS__); } \
    } while (0)

#define print_verb(fmt, ...) \
    do { struct timespec monotime; \
         clock_gettime(CLOCK_MONOTONIC, &monotime); \
         if(DO_VERB) { \
             fprintf(stdout,  "VERB:%s:%d:%s():%lld: " \
                     fmt, __FILE__, __LINE__, __func__, \
                     (long long)monotime.tv_sec, \
                     ## __VA_ARGS__); } \
    } while (0)
#else // ifdef DCE_NS3_FIX

#define print_eval(fmt, ...) \
    do { if(DO_EVAL) {fprintf(stdout,  "EVAL:" fmt, \
                              ## __VA_ARGS__); } } while (0)

#define print_log(fmt, ...) \
    do { if(DO_LOG) {fprintf(stdout,  "LOG:%s:%d:%s(): " fmt, __FILE__, \
                             __LINE__, __func__, ## __VA_ARGS__); } } while (0)

#define print_error(fmt, ...) \
    do { if(DO_ERROR) {fprintf(stderr, "ERROR:%s:%d:%s(): " fmt, __FILE__, \
                               __LINE__, __func__, ## __VA_ARGS__); } } while (0)

#define print_debug(fmt, ...) \
    do { if(DO_DEBUG) {fprintf(stdout, "DEBUG:%s:%d:%s(): " fmt, __FILE__, \
                               __LINE__, __func__, ## __VA_ARGS__); } } while (0)

#define print_verb(fmt, ...) \
    do { if(DO_VERB) {fprintf(stdout,  "VERB :%s:%d:%s(): " fmt, __FILE__, \
                              __LINE__, __func__, ## __VA_ARGS__); } } while (0)

#endif

#endif

/* end file: debug.h */

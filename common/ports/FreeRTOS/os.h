/**
 * @file os.h
 * @brief RTOS abstraction layer
 *
 * @section License
 *
 * Copyright (C) 2010-2013 Oryx Embedded. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * @author Oryx Embedded (www.oryx-embedded.com)
 * @version 1.3.8
 **/

#ifndef _OS_H
#define _OS_H

//Dependencies
#include <stddef.h>
#include <stdint.h>

#define PTR_OFFSET(addr, offset) ((void *) ((uint8_t *) (addr) + (offset)))

#define timeCompare(t1, t2) ((int32_t) ((t1) - (t2)))


#define ENABLED TRUE
#define DISABLED FALSE

#ifndef FALSE
   #define FALSE 0
#endif

#ifndef TRUE
   #define TRUE 1
#endif

#define LSB(x) ((x) & 0xFF)
#define MSB(x) (((x) >> 8) & 0xFF)

#ifdef min
   #undef min
#endif

#define min(a, b) ((a) < (b) ? (a) : (b))

#ifdef max
   #undef max
#endif

#define max(a, b) ((a) > (b) ? (a) : (b))

#ifndef arraysize
   #define arraysize(a) (sizeof(a) / sizeof(a[0]))
#endif

//Events
#define INFINITE_DELAY ((uint_t) -1)

//Invalid handle value
#define OS_INVALID_HANDLE NULL

//Types
typedef char char_t;
typedef signed int int_t;
typedef unsigned int uint_t;
typedef int bool_t;

#ifndef _WIN32
   typedef unsigned long time_t;
#endif

//OS related objects
typedef void (*TaskCode)(void *params);
typedef void OsTask;
typedef void OsEvent;
typedef void OsSemaphore;
typedef void OsMutex;
typedef void OsQueue;


/**
 * @brief Timer object
 **/

typedef struct
{
   bool_t running;
   time_t startTime;
   time_t interval;
} OsTimer;


//Scheduler specific functions
void osStart(void);

//Task management
OsTask *osTaskCreate(const char_t *name, TaskCode taskCode,
   void *params, size_t stackSize, uint_t priority);

void osTaskDelete(OsTask *task);
OsTask *osTaskGetHandle(void);
void osTaskSuspendAll(void);
void osTaskResumeAll(void);
void osTaskSwitch(void);
void osTaskSwitchFromIrq(void);

//Event specific functions
OsEvent *osEventCreate(bool_t manualReset, bool_t initialState);
void osEventClose(OsEvent *event);
void osEventSet(OsEvent *event);
void osEventReset(OsEvent *event);
bool_t osEventWait(OsEvent *event, time_t timeout);
bool_t osEventSetFromIrq(OsEvent *event);

//Semaphore specific functions
OsSemaphore *osSemaphoreCreate(uint_t maxCount, uint_t initialCount);
void osSemaphoreClose(OsSemaphore *semaphore);
bool_t osSemaphoreWait(OsSemaphore *semaphore, time_t timeout);
void osSemaphoreRelease(OsSemaphore *semaphore);

//Mutex specific functions
OsMutex *osMutexCreate(bool_t initialOwner);
void osMutexClose(OsMutex *mutex);
void osMutexAcquire(OsMutex *mutex);
void osMutexRelease(OsMutex *mutex);

//Queue specific functions
OsQueue *osQueueCreate(uint_t length, size_t itemSize);
void osQueueClose(OsQueue *queue);
bool_t osQueueSend(OsQueue *queue, const void *item, time_t timeout);
bool_t osQueueReceive(OsQueue *queue, void *item, time_t timeout);
bool_t osQueuePeek(OsQueue *queue, void *item, time_t timeout);
bool_t osQueueSendFromIrq(OsQueue *queue, const void *item, bool_t *higherPriorityTaskWoken);
bool_t osQueueReceiveFromIrq(OsQueue *queue, void *item, bool_t *higherPriorityTaskWoken);

//Timer specific functions
void osTimerStart(OsTimer *timer, time_t delay);
void osTimerStop(OsTimer *timer);
bool_t osTimerRunning(OsTimer *timer);
bool_t osTimerElapsed(OsTimer *timer);

//Memory management
void *osMemAlloc(size_t size);
void osMemFree(void *p);

//Atomic operations
uint16_t osAtomicInc16(uint16_t *n);
uint32_t osAtomicInc32(uint32_t *n);

//Time related functions
void osDelay(time_t delay);
time_t osGetTickCount(void);
time_t osGetTime(void);

const char_t *timeFormat(time_t time);
void usleep(uint_t delay);
void sleep(uint_t delay);


//#define osWaitForEvent2(event, timeout) xQueuePeek(event, NULL, timeout)

#ifdef _WIN32
   #undef min
   #undef max
   #include <stdlib.h>
   #undef min
   #undef max
   #define min(a, b) ((a) < (b) ? (a) : (b))
   #define max(a, b) ((a) > (b) ? (a) : (b))
   #define strlwr _strlwr
   #define strcasecmp _stricmp
   #define strtok_r(str, delim, p) strtok(str, delim)
   #include <time.h>
#endif

#endif

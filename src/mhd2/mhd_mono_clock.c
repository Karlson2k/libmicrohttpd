/*
  This file is part of libmicrohttpd
  Copyright (C) 2015-2024 Karlson2k (Evgeny Grin)

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

/**
 * @file src/mhd2/mhd_mono_clock.h
 * @brief  monotonic clock functions implementations
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"

#include "mhd_mono_clock.h"

#if defined(_WIN32) && ! defined(__CYGWIN__)
/* Prefer native clock source over wrappers */
#  ifdef HAVE_CLOCK_GETTIME
#    undef HAVE_CLOCK_GETTIME
#  endif /* HAVE_CLOCK_GETTIME */
#  ifdef HAVE_GETTIMEOFDAY
#    undef HAVE_GETTIMEOFDAY
#  endif /* HAVE_GETTIMEOFDAY */
#endif /* _WIN32 && ! __CYGWIN__ */

#if defined(HAVE_MACH_CONTINUOUS_APPROXIMATE_TIME) || \
  defined(HAVE_MACH_APPROXIMATE_TIME)
/* Use mach_*_time() functions family */
#  define mhd_USE_MACH_TIME     1
#endif

#ifdef HAVE_TIME_H
#  include <time.h>
#endif /* HAVE_TIME_H */
#ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
#endif /* HAVE_SYS_TIME_H */

#if defined(HAVE_CLOCK_GET_TIME) || \
  defined(mhd_USE_MACH_TIME)
/* for host_get_clock_service(), mach_host_self(), mach_task_self() */
/* also for compatibility with old headers structure */
#  include <mach/mach.h>
#endif

#ifdef HAVE_CLOCK_GET_TIME
/* for clock_get_time() */
#  include <mach/clock.h>
#endif /* HAVE_CLOCK_GET_TIME */

#if defined(mhd_USE_MACH_TIME)
#  include <mach/mach_time.h>
#endif

#ifdef _WIN32
#  include <windows.h>
#endif /* _WIN32 */

#include "mhd_assert.h"


#ifdef HAVE_CLOCK_GETTIME
#  ifdef CLOCK_REALTIME
#    define mhd_CLOCK_ID_UNWANTED CLOCK_REALTIME
#  else  /* !CLOCK_REALTIME */
#    define mhd_CLOCK_ID_UNWANTED ((clockid_t) -2)
#  endif /* !CLOCK_REALTIME */

static clockid_t mono_clock_id = mhd_CLOCK_ID_UNWANTED;
#endif /* HAVE_CLOCK_GETTIME */

/* sync clocks; reduce chance of value wrap */
#if defined(HAVE_CLOCK_GETTIME) || defined(HAVE_CLOCK_GET_TIME) || \
  defined(HAVE_GETHRTIME)
static time_t mono_clock_start;
#endif /* HAVE_CLOCK_GETTIME || HAVE_CLOCK_GET_TIME || HAVE_GETHRTIME */

#ifdef HAVE_CLOCK_GET_TIME
#  if ! defined(SYSTEM_CLOCK) && defined(REALTIME_CLOCK)
#    define SYSTEM_CLOCK REALTIME_CLOCK
#  endif
#  define mhd_CLOCK_SERV_INVALID ((clock_serv_t) -2)

static clock_serv_t mono_clock_service = mhd_CLOCK_SERV_INVALID;
#endif /* HAVE_CLOCK_GET_TIME */

#if defined(mhd_USE_MACH_TIME)

/* The numerator to calculate milliseconds */
static uint_fast32_t mach_time_mls_numer = 0;
/* The denominator to calculate milliseconds */
static uint_fast64_t mach_time_mls_denom = 0;
/* The starting value. Used to lower chance of the final value wrap. */
static uint64_t mach_time_start; /* uint64_t is always available with mach */
#endif

#ifdef HAVE_GETHRTIME
static hrtime_t hrtime_start;
#endif /* HAVE_GETHRTIME */

#ifdef _WIN32
#  if _WIN32_WINNT >= 0x0600
static uint64_t tick_start;     /* 'uint64_t' is available on W32 always */
#  else  /* _WIN32_WINNT < 0x0600 */
static uint64_t perf_freq;      /* 'uint64_t' is available on W32 always */
static uint64_t perf_start;     /* 'uint64_t' is available on W32 always */
#  endif /* _WIN32_WINNT < 0x0600 */
#endif /* _WIN32 */

/* Start values for fallback sources */
#if defined(HAVE_TIMESPEC_GET) || defined(HAVE_GETTIMEOFDAY)
/* The start value shared for timespec_get() and gettimeofday () */
static time_t gettime_start;
#define mhd_HAVE_GETTIME_START_VAR      1
#endif /* HAVE_TIMESPEC_GET || HAVE_GETTIMEOFDAY */
static time_t sys_clock_start;


#ifdef HAVE_CLOCK_GET_TIME
/**
 * Initialise Darwin-specific resources for 'clock_get_time()'
 * @param[out] cur_time the optional pointer to get the current time value,
 *                      can be NULL
 * @return 'true' if succeed,
 *         'false' if failed
 */
static MHD_FN_PAR_OUT_ (1) MHD_FN_MUST_CHECK_RESULT_ bool
mclock_init_clock_get_time (mach_timespec_t *cur_time)
{
  mhd_assert (mhd_CLOCK_SERV_INVALID == mono_clock_service);

  if (KERN_SUCCESS == host_get_clock_service (mach_host_self (),
                                              SYSTEM_CLOCK,
                                              &mono_clock_service))
    return false;

  if (NULL != cur_time)
  {
    if (KERN_SUCCESS != clock_get_time (mono_clock_service,
                                        cur_time))
    {
      (void) mach_port_deallocate (mach_task_self (),
                                   mono_clock_service);
      mono_clock_service = mhd_CLOCK_SERV_INVALID;
      return false;
    }
  }

  return true;
}


/**
 * De-initialise Darwin-specific resources for 'clock_get_time()'
 */
static void
mclock_deinit_clock_get_time (void)
{
  mhd_assert (mhd_CLOCK_SERV_INVALID != mono_clock_service);
  (void) mach_port_deallocate (mach_task_self (),
                               mono_clock_service);
  mono_clock_service = mhd_CLOCK_SERV_INVALID;
}


#else  /* HAVE_CLOCK_GET_TIME */
/* No-op implementation */
#  define mclock_init_clock_get_time(ptr) ((void) ptr, false)
#  define mclock_deinit_clock_get_time() ((void) 0)
#endif /* HAVE_CLOCK_GET_TIME */

#if defined(mhd_USE_MACH_TIME)

/**
 * Calculate greatest common divisor.
 * Based on Euclidean algorithm as it is fast enough and more compact then
 * binary GCD algorithm.
 * @param a the first value
 * @param b the second value
 * @return the greatest common divisor,
 *         if either of the input values ​​is zero, the other input value returned
 */
MHD_static_inline_ uint_fast32_t
mclock_gcd (uint_fast32_t a, uint_fast32_t b)
{
  if (0 == b)
    return a;

  while (1)
  {
    a %= b;
    if (0 == a)
      return b;
    b %= a;
    if (0 == b)
      break;
  }
  return a;
}


/**
 * Initialise data for mach_time functions
 * @return 'true' if succeed,
 *         'false' if failed
 */
static bool
mclock_init_mach_time (void)
{
  struct mach_timebase_info mach_tb_info;
  uint_fast32_t comm_div;
  static const uint_fast32_t nanosec_in_milisec = 1000u * 1000u;

  mhd_assert ((0 != mach_time_mls_denom) || (0 == mach_time_mls_numer));

  if (KERN_SUCCESS != mach_timebase_info (&mach_tb_info))
    return false;

  mhd_assert (0 != mach_tb_info.numer); /* Help code analysers */
  mhd_assert (0 != mach_tb_info.denom); /* Help code analysers */

  comm_div = mclock_gcd (mach_tb_info.numer, nanosec_in_milisec);
  mach_time_mls_numer = mach_tb_info.numer / comm_div;
  mach_time_mls_denom =
    ((uint_fast64_t) mach_tb_info.denom) * (nanosec_in_milisec / comm_div);

  return true;
}
#else  /* ! mhd_USE_MACH_TIME */
#  define mclock_init_mach_time()     (true)
#endif /* ! mhd_USE_MACH_TIME */

/**
 * Type of monotonic clock source
 */
enum mhd_mono_clock_source
{
  /**
   * No monotonic clock source.
   */
  mhd_MCLOCK_SOUCE_NO_SOURCE = 0

#ifdef HAVE_CLOCK_GETTIME
  ,
  /**
   * clock_gettime() with specific clock.
   * Generic standard source.
   */
  mhd_MCLOCK_SOUCE_GETTIME
#endif /* HAVE_CLOCK_GETTIME */

#if defined(mhd_USE_MACH_TIME)
  ,
  /**
   * mach_continuous_approximate_time() or mach_approximate_time()
   * with coefficient.
   * Darwin-specific clock source.
   */
  mhd_MCLOCK_SOUCE_MACH_TIME
#endif /* mhd_USE_MACH_TIME */

#ifdef HAVE_CLOCK_GET_TIME
  ,
  /**
   * clock_get_time() with specific clock service.
   * Darwin-specific clock source.
   */
  mhd_MCLOCK_SOUCE_GET_TIME
#endif /* HAVE_CLOCK_GET_TIME */

#ifdef HAVE_GETHRTIME
  ,
  /**
   * gethrtime() / 1000000
   * HP-UX and Solaris monotonic clock source.
   */
  mhd_MCLOCK_SOUCE_GETHRTIME
#endif /* HAVE_GETHRTIME */

#ifdef _WIN32
#if _WIN32_WINNT >= 0x0600
  ,
  /**
   * GetTickCount64()
   * W32 tick counter source.
   */
  mhd_MCLOCK_SOUCE_GETTICKCOUNT64
#else  /* _WIN32_WINNT < 0x0600 */

  ,
  /**
   * QueryPerformanceCounter() / QueryPerformanceFrequency()
   * Older W32 monotonic time source.
   */
  mhd_MCLOCK_SOUCE_PERFCOUNTER
#endif /* _WIN32_WINNT < 0x0600 */
#endif /* _WIN32 */
};

/**
 * The active source of the monotonic time
 */
static enum mhd_mono_clock_source mono_clock_source =
  mhd_MCLOCK_SOUCE_NO_SOURCE;

/**
 * Initialise milliseconds counters.
 */
MHD_INTERNAL void
mhd_monotonic_msec_counter_init (void)
{
#ifdef HAVE_CLOCK_GET_TIME
  mach_timespec_t cur_time;
#endif /* HAVE_CLOCK_GET_TIME */
#ifdef HAVE_CLOCK_GETTIME
  struct timespec ts;

  mono_clock_id = mhd_CLOCK_ID_UNWANTED;
#endif /* HAVE_CLOCK_GETTIME */
#ifdef HAVE_CLOCK_GET_TIME
  mono_clock_service = mhd_CLOCK_SERV_INVALID;
#endif /* HAVE_CLOCK_GET_TIME */

  mono_clock_source = mhd_MCLOCK_SOUCE_NO_SOURCE;

  /* Try specialised fast sources */
#ifdef _WIN32
#if _WIN32_WINNT >= 0x0600
  /* W32 Vista or later specific monotonic clock */
  /* Available since Vista, ~15ms accuracy */
  if (1)
  {
    tick_start = GetTickCount64 ();
    mono_clock_source = mhd_MCLOCK_SOUCE_GETTICKCOUNT64;
  }
  else
#else  /* _WIN32_WINNT < 0x0600 */
  /* W32 specific monotonic clock */
  /* Available on Windows 2000 and later */
  if (1)
  {
    LARGE_INTEGER freq;
    LARGE_INTEGER perf_counter;

    (void) QueryPerformanceFrequency (&freq);       /* never fail on XP and later */
    (void) QueryPerformanceCounter (&perf_counter); /* never fail on XP and later */
    perf_freq = (uint64_t) freq.QuadPart;
    perf_start = (uint64_t) perf_counter.QuadPart;
    mono_clock_source = mhd_MCLOCK_SOUCE_PERFCOUNTER;
  }
  else
#endif /* _WIN32_WINNT < 0x0600 */
#endif /* _WIN32 */
#if defined(mhd_USE_MACH_TIME)
  /* Mach (Darwin) specific monotonic clock */
  /* mach_continuous_approximate_time() counts time in suspend,
     mach_approximate_time() does not count time in suspend.
     Both function are fast and used as a basis for universal portable functions
     on Darwin. */
  if (mclock_init_mach_time ())
  {
#  ifdef HAVE_MACH_CONTINUOUS_APPROXIMATE_TIME
    mach_time_start = mach_continuous_approximate_time ();
#  else  /* HAVE_MACH_APPROXIMATE_TIME */
    mach_time_start = mach_approximate_time ();
#  endif
    mono_clock_source = mhd_MCLOCK_SOUCE_MACH_TIME;
  }
  else
#endif /* mhd_USE_MACH_TIME */

  /* Try universally available sources */
#ifdef HAVE_CLOCK_GETTIME
#ifdef CLOCK_MONOTONIC_COARSE
  /* Linux-specific fast value-getting clock */
  /* Can be affected by frequency adjustment and doesn't count time
   * in suspend, but preferred since it's fast */
  if (0 == clock_gettime (CLOCK_MONOTONIC_COARSE,
                          &ts))
  {
    mono_clock_id = CLOCK_MONOTONIC_COARSE;
    mono_clock_start = ts.tv_sec;
    mono_clock_source = mhd_MCLOCK_SOUCE_GETTIME;
  }
  else
#endif /* CLOCK_MONOTONIC_COARSE */
#ifdef CLOCK_MONOTONIC_FAST
  /* FreeBSD/DragonFly fast value-getting clock */
  /* Can be affected by frequency adjustment, but preferred since it's fast */
  if (0 == clock_gettime (CLOCK_MONOTONIC_FAST,
                          &ts))
  {
    mono_clock_id = CLOCK_MONOTONIC_FAST;
    mono_clock_start = ts.tv_sec;
    mono_clock_source = mhd_MCLOCK_SOUCE_GETTIME;
  }
  else
#endif /* CLOCK_MONOTONIC_COARSE */
#ifdef CLOCK_UPTIME_FAST
  /* FreeBSD/DragonFly fast value-getting clock */
  /* Can be affected by frequency adjustment and doesn't count time
   * in suspend, but preferred since it's fast */
  if (0 == clock_gettime (CLOCK_UPTIME_FAST,
                          &ts))
  {
    mono_clock_id = CLOCK_MONOTONIC_FAST;
    mono_clock_start = ts.tv_sec;
    mono_clock_source = mhd_MCLOCK_SOUCE_GETTIME;
  }
  else
#endif /* CLOCK_UPTIME_FAST */
#ifdef CLOCK_MONOTONIC_RAW_APPROX
  /* Darwin-specific clock */
  /* Not affected by frequency adjustment, returns clock value cached at
   * context switch. Can be "milliseconds old", but it's fast. */
  if (0 == clock_gettime (CLOCK_MONOTONIC_RAW_APPROX,
                          &ts))
  {
    mono_clock_id = CLOCK_MONOTONIC_RAW_APPROX;
    mono_clock_start = ts.tv_sec;
    mono_clock_source = mhd_MCLOCK_SOUCE_GETTIME;
  }
  else
#endif /* CLOCK_MONOTONIC_RAW */
#ifdef CLOCK_UPTIME_RAW_APPROX
  /* Darwin-specific clock */
  /* Not affected by frequency adjustment, but doesn't count time in suspend.
   * Returns clock value cached at context switch.
   * Can be "milliseconds old", but it's fast. */
  if (0 == clock_gettime (CLOCK_UPTIME_RAW_APPROX,
                          &ts))
  {
    mono_clock_id = CLOCK_UPTIME_RAW_APPROX;
    mono_clock_start = ts.tv_sec;
    mono_clock_source = mhd_MCLOCK_SOUCE_GETTIME;
  }
  else
#endif /* CLOCK_UPTIME_RAW_APPROX */
#ifdef CLOCK_MONOTONIC_RAW
  /* Linux and Darwin clock */
  /* Not affected by frequency adjustment,
   * on Linux doesn't count time in suspend */
  if (0 == clock_gettime (CLOCK_MONOTONIC_RAW,
                          &ts))
  {
    mono_clock_id = CLOCK_MONOTONIC_RAW;
    mono_clock_start = ts.tv_sec;
    mono_clock_source = mhd_MCLOCK_SOUCE_GETTIME;
  }
  else
#endif /* CLOCK_MONOTONIC_RAW */
#ifdef CLOCK_BOOTTIME
  /* Counts time in suspend on Linux so it's real monotonic, */
  /* but can be slower value-getting than other clocks */
  if (0 == clock_gettime (CLOCK_BOOTTIME,
                          &ts))
  {
    mono_clock_id = CLOCK_BOOTTIME;
    mono_clock_start = ts.tv_sec;
    mono_clock_source = mhd_MCLOCK_SOUCE_GETTIME;
  }
  else
#endif /* CLOCK_BOOTTIME */
#ifdef CLOCK_MONOTONIC
  /* Monotonic clock */
  /* Widely supported, may be affected by frequency adjustment */
  /* On Linux it's not truly monotonic as it doesn't count time in suspend */
  if (0 == clock_gettime (CLOCK_MONOTONIC,
                          &ts))
  {
    mono_clock_id = CLOCK_MONOTONIC;
    mono_clock_start = ts.tv_sec;
    mono_clock_source = mhd_MCLOCK_SOUCE_GETTIME;
  }
  else
#endif /* CLOCK_MONOTONIC */
#ifdef CLOCK_UPTIME
  /* non-Linux clock */
  /* Doesn't count time in suspend */
  if (0 == clock_gettime (CLOCK_UPTIME,
                          &ts))
  {
    mono_clock_id = CLOCK_UPTIME;
    mono_clock_start = ts.tv_sec;
    mono_clock_source = mhd_MCLOCK_SOUCE_GETTIME;
  }
  else
#endif /* CLOCK_BOOTTIME */
#endif /* HAVE_CLOCK_GETTIME */
#ifdef HAVE_CLOCK_GET_TIME
  /* Darwin-specific monotonic clock source */
  /* Should be monotonic as clock_set_time function always unconditionally */
  /* failed on modern kernels */
  if (mclock_init_clock_get_time (&cur_time))
  {
    mono_clock_start = cur_time.tv_sec;
    mono_clock_source = mhd_MCLOCK_SOUCE_GET_TIME;
  }
  else
#endif /* HAVE_CLOCK_GET_TIME */
#ifdef HAVE_CLOCK_GETTIME
#ifdef CLOCK_HIGHRES
  /* Solaris-specific monotonic high-resolution clock */
  /* Not preferred due to be potentially resource-hungry */
  if (0 == clock_gettime (CLOCK_HIGHRES,
                          &ts))
  {
    mono_clock_id = CLOCK_HIGHRES;
    mono_clock_start = ts.tv_sec;
    mono_clock_source = mhd_MCLOCK_SOUCE_GETTIME;
  }
  else
#endif /* CLOCK_HIGHRES */
#endif /* HAVE_CLOCK_GETTIME */
#ifdef HAVE_GETHRTIME
  /* HP-UX and Solaris monotonic clock */
  /* Not preferred due to be potentially resource-hungry */
  if (1)
  {
    hrtime_start = gethrtime ();
    mono_clock_source = mhd_MCLOCK_SOUCE_GETHRTIME;
  }
  else
#endif /* HAVE_GETHRTIME */
  (void) 0; /* The end of if-else chain */

  /* Initialise start values for fallbacks */
#ifdef HAVE_TIMESPEC_GET
  if (1)
  {
    struct timespec tsg;
    if (TIME_UTC == timespec_get (&tsg, TIME_UTC))
      gettime_start = tsg.tv_sec;
    else
      gettime_start = 0;
  }
#elif defined(HAVE_GETTIMEOFDAY)
  if (1)
  {
    struct timeval tv;
    if (0 == gettimeofday (&tv, NULL))
      gettime_start = tv.tv_sec;
    else
      gettime_start = 0;
  }
#endif /* HAVE_GETTIMEOFDAY */

  sys_clock_start = time (NULL);
#ifdef mhd_HAVE_GETTIME_START_VAR
  if (((time_t) -1) == sys_clock_start)
    sys_clock_start = gettime_start;
#endif /* mhd_HAVE_GETTIME_START_VAR */
}


/**
 * Deinitialise milliseconds counters by freeing any allocated resources
 */
MHD_INTERNAL void
mhd_monotonic_msec_counter_finish (void)
{
#ifdef HAVE_CLOCK_GET_TIME
  if (mhd_MCLOCK_SOUCE_GET_TIME == mono_clock_source)
    mclock_deinit_clock_get_time ();
#endif
}


MHD_INTERNAL bool
mhd_monotonic_msec_counter_re_init (void)
{
#ifdef HAVE_CLOCK_GET_TIME
  if (mhd_MCLOCK_SOUCE_GET_TIME == mono_clock_source)
  {
    if (! mclock_init_clock_get_time ())
    {
      /* Fallback to full initialisation */
      return mhd_monotonic_msec_counter_init ();
    }
  }
#endif
  return true;
}


/**
 * Monotonic milliseconds counter, useful for timeout calculation.
 * Tries to be not affected by manually setting the system real time
 * clock or adjustments by NTP synchronization.
 *
 * @return number of microseconds from some fixed moment
 */
MHD_INTERNAL uint_fast64_t
mhd_monotonic_msec_counter (void)
{
  enum mhd_mono_clock_source source_to_use;

  /* Optimise binary if the source is fixed */
#if defined(_WIN32) && _WIN32_WINNT >= 0x0600
  if (1)
    source_to_use = mhd_MCLOCK_SOUCE_GETTICKCOUNT64;
  else
#endif /* _WIN32 && _WIN32_WINNT >= 0x0600 */
  source_to_use = mono_clock_source;

  mhd_assert (mono_clock_source == source_to_use);

  switch (source_to_use)
  {
  case mhd_MCLOCK_SOUCE_NO_SOURCE:
    break; /* Use fallbacks */
#ifdef HAVE_CLOCK_GETTIME
  case mhd_MCLOCK_SOUCE_GETTIME:
    mhd_assert (mhd_CLOCK_ID_UNWANTED != mono_clock_id);
    if (1)
    {
      struct timespec ts;
      if (0 == clock_gettime (mono_clock_id,
                              &ts))
        return (uint_fast64_t)
               (((uint_fast64_t) (ts.tv_sec - mono_clock_start)) * 1000
                + (uint_fast64_t) (ts.tv_nsec / 1000000));
    }
    break;
#endif /* HAVE_CLOCK_GETTIME */

#if defined(mhd_USE_MACH_TIME)
  case mhd_MCLOCK_SOUCE_MACH_TIME:
    mhd_assert (0 != mach_time_mls_numer);
    mhd_assert (0 != mach_time_mls_denom);
    if (1)
    {
      uint64_t t;
#  ifdef HAVE_MACH_CONTINUOUS_APPROXIMATE_TIME
      t = mach_continuous_approximate_time () - mach_time_start;
#  else  /* HAVE_MACH_APPROXIMATE_TIME */
      t = mach_approximate_time () - mach_time_start;
#  endif
#  ifndef MHD_FAVOR_SMALL_CODE
      if (1 == mach_time_mls_numer) /* Shortcut for the most common situation */
        return (uint_fast64_t) t / mach_time_mls_denom;
#  endif /* MHD_FAVOR_SMALL_CODE */

      /* Avoid float point arithmetic as it lower precision on higher values.
         Two stages calculations to avoid overflow of integer values and keep
         precision high enough. */
      return (((uint_fast64_t) t) / mach_time_mls_denom) * mach_time_mls_numer
             + ((((uint_fast64_t) t) % mach_time_mls_denom)
                * mach_time_mls_numer) / mach_time_mls_denom;
    }
    break;
#endif /* mhd_USE_MACH_TIME */

#ifdef HAVE_CLOCK_GET_TIME
  case mhd_MCLOCK_SOUCE_GET_TIME:
    mhd_assert (mhd_CLOCK_SERV_INVALID != mono_clock_service);
    if (1)
    {
      mach_timespec_t cur_time;

      if (KERN_SUCCESS == clock_get_time (mono_clock_service,
                                          &cur_time))
        return (uint_fast64_t)
               (((uint_fast64_t) (cur_time.tv_sec - mono_clock_start)) * 1000
                + (uint_fast64_t) (cur_time.tv_nsec / 1000000));
    }
    break;
#endif /* HAVE_CLOCK_GET_TIME */

#ifdef HAVE_GETHRTIME
  case mhd_MCLOCK_SOUCE_GETHRTIME:
    return ((uint_fast64_t) (gethrtime () - hrtime_start)) / 1000000;
#endif /* HAVE_GETHRTIME */

#ifdef _WIN32
#if _WIN32_WINNT >= 0x0600
  case mhd_MCLOCK_SOUCE_GETTICKCOUNT64:
    return (uint_fast64_t) (GetTickCount64 () - tick_start);
#else  /* _WIN32_WINNT < 0x0600 */
  case mhd_MCLOCK_SOUCE_PERFCOUNTER:
    mhd_assert (0 != perf_freq);
    if (1)
    {
      LARGE_INTEGER perf_counter;
      uint_fast64_t num_ticks;

      (void) QueryPerformanceCounter (&perf_counter);   /* never fail on XP and later */
      num_ticks = (uint_fast64_t) (perf_counter.QuadPart - perf_start);
      return ((num_ticks / perf_freq) * 1000)
             + (((num_ticks % perf_freq) * 1000) / perf_freq);
    }
    break;
#endif /* _WIN32_WINNT < 0x0600 */
#endif /* _WIN32 */
  default:
    mhd_assert (0 && "Impossible value");
    MHD_UNREACHABLE_;
    break;
  }

  /* Fallbacks, affected by system time change */
#ifdef HAVE_TIMESPEC_GET
  if (1)
  {
    struct timespec ts;
    if (TIME_UTC == timespec_get (&ts, TIME_UTC))
      return (uint_fast64_t)
             (((uint_fast64_t) (ts.tv_sec - gettime_start)) * 1000
              + (uint_fast64_t) (ts.tv_nsec / 1000000));
  }
#elif defined(HAVE_GETTIMEOFDAY)
  if (1)
  {
    struct timeval tv;
    if (0 == gettimeofday (&tv, NULL))
      return (uint_fast64_t)
             (((uint_fast64_t) (tv.tv_sec - gettime_start)) * 1000
              + (uint_fast64_t) (tv.tv_usec / 1000));
  }
#endif /* HAVE_GETTIMEOFDAY */

  /* The last resort fallback with very low resolution */
#ifdef mhd_HAVE_GETTIME_START_VAR
  if (1)
  {
    time_t time_now;
    time_now = time (NULL);
    if (((time_t) -1) != time_now)
      return ((uint_fast64_t) (time_now - sys_clock_start)) * 1000;
  }
  return 0; /* No time source, should not really happen */
#else  /* ! mhd_HAVE_GETTIME_START_VAR */
  return ((uint_fast64_t) (time (NULL) - sys_clock_start)) * 1000;
#endif
}

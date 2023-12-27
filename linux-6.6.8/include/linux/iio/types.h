/* SPDX-License-Identifier: GPL-2.0-only */
/* industrial I/O data types needed both in and out of kernel
 *
 * Copyright (c) 2008 Jonathan Cameron
 */

#ifndef _IIO_TYPES_H_
#define _IIO_TYPES_H_

#include <uapi/linux/iio/types.h>

enum iio_event_info {
	IIO_EV_INFO_ENABLE,
	IIO_EV_INFO_VALUE,
	IIO_EV_INFO_HYSTERESIS,
	IIO_EV_INFO_PERIOD,
	IIO_EV_INFO_HIGH_PASS_FILTER_3DB,
	IIO_EV_INFO_LOW_PASS_FILTER_3DB,
	IIO_EV_INFO_TIMEOUT,
	IIO_EV_INFO_RESET_TIMEOUT,
	IIO_EV_INFO_TAP2_MIN_DELAY,
	IIO_EV_INFO_RUNNING_PERIOD,
	IIO_EV_INFO_RUNNING_COUNT,
};

#define IIO_VAL_INT 1
#define IIO_VAL_INT_PLUS_MICRO 2
#define IIO_VAL_INT_PLUS_NANO 3
#define IIO_VAL_INT_PLUS_MICRO_DB 4
#define IIO_VAL_INT_MULTIPLE 5
#define IIO_VAL_INT_64 6 /* 64-bit data, val is lower 32 bits */
#define IIO_VAL_FRACTIONAL 10
#define IIO_VAL_FRACTIONAL_LOG2 11
#define IIO_VAL_CHAR 12

enum iio_available_type {
	IIO_AVAIL_LIST,
	IIO_AVAIL_RANGE,
};

enum iio_chan_info_enum {
	IIO_CHAN_INFO_RAW = 0,
	IIO_CHAN_INFO_PROCESSED,
	IIO_CHAN_INFO_SCALE,
	IIO_CHAN_INFO_OFFSET,
	IIO_CHAN_INFO_CALIBSCALE,
	IIO_CHAN_INFO_CALIBBIAS,
	IIO_CHAN_INFO_PEAK,
	IIO_CHAN_INFO_PEAK_SCALE,
	IIO_CHAN_INFO_QUADRATURE_CORRECTION_RAW,
	IIO_CHAN_INFO_AVERAGE_RAW,
	IIO_CHAN_INFO_LOW_PASS_FILTER_3DB_FREQUENCY,
	IIO_CHAN_INFO_HIGH_PASS_FILTER_3DB_FREQUENCY,
	IIO_CHAN_INFO_SAMP_FREQ,
	IIO_CHAN_INFO_FREQUENCY,
	IIO_CHAN_INFO_PHASE,
	IIO_CHAN_INFO_HARDWAREGAIN,
	IIO_CHAN_INFO_HYSTERESIS,
	IIO_CHAN_INFO_HYSTERESIS_RELATIVE,
	IIO_CHAN_INFO_INT_TIME,
	IIO_CHAN_INFO_ENABLE,
	IIO_CHAN_INFO_CALIBHEIGHT,
	IIO_CHAN_INFO_CALIBWEIGHT,
	IIO_CHAN_INFO_DEBOUNCE_COUNT,
	IIO_CHAN_INFO_DEBOUNCE_TIME,
	IIO_CHAN_INFO_CALIBEMISSIVITY,
	IIO_CHAN_INFO_OVERSAMPLING_RATIO,
	IIO_CHAN_INFO_THERMOCOUPLE_TYPE,
	IIO_CHAN_INFO_CALIBAMBIENT,
	IIO_CHAN_INFO_ZEROPOINT,
};

#endif /* _IIO_TYPES_H_ */

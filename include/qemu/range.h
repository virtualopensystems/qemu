#ifndef QEMU_RANGE_H
#define QEMU_RANGE_H

#include <inttypes.h>
#include <qemu/typedefs.h>
#include "qemu/queue.h"

/*
 * Operations on 64 bit address ranges.
 * Notes:
 *   - ranges must not wrap around 0, but can include the last byte ~0x0LL.
 *   - this can not represent a full 0 to ~0x0LL range.
 */

/* A structure representing a range of addresses. */
struct Range {
    uint64_t begin; /* First byte of the range, or 0 if empty. */
    uint64_t end;   /* 1 + the last byte. 0 if range empty or ends at ~0x0LL. */
};

static inline void range_extend(Range *range, Range *extend_by)
{
    if (!extend_by->begin && !extend_by->end) {
        return;
    }
    if (!range->begin && !range->end) {
        *range = *extend_by;
        return;
    }
    if (range->begin > extend_by->begin) {
        range->begin = extend_by->begin;
    }
    /* Compare last byte in case region ends at ~0x0LL */
    if (range->end - 1 < extend_by->end - 1) {
        range->end = extend_by->end;
    }
}

/* Get last byte of a range from offset + length.
 * Undefined for ranges that wrap around 0. */
static inline uint64_t range_get_last(uint64_t offset, uint64_t len)
{
    return offset + len - 1;
}

/* Check whether a given range covers a given byte. */
static inline int range_covers_byte(uint64_t offset, uint64_t len,
                                    uint64_t byte)
{
    return offset <= byte && byte <= range_get_last(offset, len);
}

/* Check whether 2 given ranges overlap.
 * Undefined if ranges that wrap around 0. */
static inline int ranges_overlap(uint64_t first1, uint64_t len1,
                                 uint64_t first2, uint64_t len2)
{
    uint64_t last1 = range_get_last(first1, len1);
    uint64_t last2 = range_get_last(first2, len2);

    return !(last2 < first1 || last1 < first2);
}

typedef struct SignedRangeList SignedRangeList;

typedef struct SignedRange {
    int64_t start;
    int64_t length;

    QTAILQ_ENTRY(SignedRange) entry;
} SignedRange;

QTAILQ_HEAD(SignedRangeList, SignedRange);

static inline int64_t s_range_end(int64_t start, int64_t length)
{
    return start + length - 1;
}

/* negative length or overflow */
static inline bool s_range_overflow(int64_t start, int64_t length)
{
    return s_range_end(start, length) < start;
}

static inline SignedRange *s_range_new(int64_t start, int64_t length)
{
    SignedRange *range = NULL;

    if (s_range_overflow(start, length)) {
        return NULL;
    }

    range = g_malloc0(sizeof(*range));
    range->start = start;
    range->length = length;

    return range;
}

static inline void s_range_free(SignedRange *range)
{
    g_free(range);
}

static inline bool s_range_overlap(int64_t start1, int64_t length1,
                                   int64_t start2, int64_t length2)
{
    return !((start1 + length1) < start2 || (start2 + length2) < start1);
}

static inline int s_range_join(SignedRange *range,
                               int64_t start, int64_t length)
{
    if (s_range_overflow(start, length)) {
        return -1;
    }

    if (s_range_overlap(range->start, range->length, start, length)) {
        int64_t end = s_range_end(range->start, range->length);
        if (end < s_range_end(start, length)) {
            end = s_range_end(start, length);
        }
        if (range->start > start) {
            range->start = start;
        }
        range->length = end - range->start + 1;
        return 0;
    }

    return -1;
}

static inline int s_range_compare(int64_t start1, int64_t length1,
                                  int64_t start2, int64_t length2)
{
    if (start1 == start2 && length1 == length2) {
        return 0;
    } else if (s_range_end(start1, length1) <
               s_range_end(start2, length2)) {
        return -1;
    } else {
        return 1;
    }
}

/* Add range to list. Keep them sorted, and merge ranges whenever possible */
static inline bool range_list_add(SignedRangeList *list,
                                  int64_t start, int64_t length)
{
    SignedRange *r, *next, *new_range = NULL, *cur = NULL;

    if (s_range_overflow(start, length)) {
        return false;
    }

    QTAILQ_FOREACH_SAFE(r, list, entry, next) {
        if (s_range_overlap(r->start, r->length, start, length)) {
            s_range_join(r, start, length);
            break;
        } else if (s_range_compare(start, length, r->start, r->length) < 0) {
            cur = r;
            break;
        }
    }

    if (!r) {
        new_range = s_range_new(start, length);
        QTAILQ_INSERT_TAIL(list, new_range, entry);
    } else if (cur) {
        new_range = s_range_new(start, length);
        QTAILQ_INSERT_BEFORE(cur, new_range, entry);
    } else {
        SignedRange *next = QTAILQ_NEXT(r, entry);
        while (next && s_range_overlap(r->start, r->length,
                                       next->start, next->length)) {
            s_range_join(r, next->start, next->length);
            QTAILQ_REMOVE(list, next, entry);
            s_range_free(next);
            next = QTAILQ_NEXT(r, entry);
        }
    }

    return true;
}

#endif

/*
 * String parsing visitor
 *
 * Copyright Red Hat, Inc. 2012
 *
 * Author: Paolo Bonzini <pbonzini@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 *
 */

#include "qemu-common.h"
#include "qapi/string-input-visitor.h"
#include "qapi/visitor-impl.h"
#include "qapi/qmp/qerror.h"
#include "qemu/option.h"
#include "qemu/queue.h"
#include "qemu/range.h"


struct StringInputVisitor
{
    Visitor visitor;

    bool head;

    SignedRangeList *ranges;
    SignedRange *cur_range;
    int64_t cur;

    const char *string;
};

static void parse_str(StringInputVisitor *siv, Error **errp)
{
    char *str = (char *) siv->string;
    long long start, end;
    SignedRange *r, *next;
    char *endptr;

    if (siv->ranges) {
        return;
    }

    siv->ranges = g_malloc0(sizeof(*siv->ranges));
    QTAILQ_INIT(siv->ranges);
    errno = 0;
    do {
        start = strtoll(str, &endptr, 0);
        if (errno == 0 && endptr > str && INT64_MIN <= start &&
            start <= INT64_MAX) {
            if (*endptr == '\0') {
                if (!range_list_add(siv->ranges, start, 1)) {
                    goto error;
                }
                str = NULL;
            } else if (*endptr == '-') {
                str = endptr + 1;
                end = strtoll(str, &endptr, 0);
                if (errno == 0 && endptr > str &&
                    INT64_MIN <= end && end <= INT64_MAX && start <= end &&
                    (start > INT64_MAX - 65536 ||
                     end < start + 65536)) {
                    if (*endptr == '\0') {
                        if (!range_list_add(siv->ranges, start,
                                            end - start + 1)) {
                            goto error;
                        }
                        str = NULL;
                    } else if (*endptr == ',') {
                        str = endptr + 1;
                        if (!range_list_add(siv->ranges, start,
                                            end - start + 1)) {
                            goto error;
                        }
                    } else {
                        goto error;
                    }
                } else {
                    goto error;
                }
            } else if (*endptr == ',') {
                str = endptr + 1;
                if (!range_list_add(siv->ranges, start, 1)) {
                    goto error;
                }
            } else {
                goto error;
            }
        } else {
            goto error;
        }
    } while (str);

    return;
error:
    if (siv->ranges) {
        QTAILQ_FOREACH_SAFE(r, siv->ranges, entry, next) {
            QTAILQ_REMOVE(siv->ranges, r, entry);
            g_free(r);
        }
        g_free(siv->ranges);
        siv->ranges = NULL;
    }
}

static void
start_list(Visitor *v, const char *name, Error **errp)
{
    StringInputVisitor *siv = DO_UPCAST(StringInputVisitor, visitor, v);

    parse_str(siv, errp);

    if (siv->ranges) {
        siv->cur_range = QTAILQ_FIRST(siv->ranges);
        if (siv->cur_range) {
            siv->cur = siv->cur_range->start;
        }
    }
}

static GenericList *
next_list(Visitor *v, GenericList **list, Error **errp)
{
    StringInputVisitor *siv = DO_UPCAST(StringInputVisitor, visitor, v);
    GenericList **link;

    if (!siv->ranges || !siv->cur_range) {
        return NULL;
    }

    if (siv->cur < siv->cur_range->start ||
        siv->cur >= (siv->cur_range->start + siv->cur_range->length)) {
        siv->cur_range = QTAILQ_NEXT(siv->cur_range, entry);
        if (siv->cur_range) {
            siv->cur = siv->cur_range->start;
        } else {
            return NULL;
        }
    }

    if (siv->head) {
        link = list;
        siv->head = false;
    } else {
        link = &(*list)->next;
    }

    *link = g_malloc0(sizeof **link);
    return *link;
}

static void
end_list(Visitor *v, Error **errp)
{
    StringInputVisitor *siv = DO_UPCAST(StringInputVisitor, visitor, v);
    siv->head = true;
}

static void parse_type_int(Visitor *v, int64_t *obj, const char *name,
                           Error **errp)
{
    StringInputVisitor *siv = DO_UPCAST(StringInputVisitor, visitor, v);

    if (!siv->string) {
        error_set(errp, QERR_INVALID_PARAMETER_TYPE, name ? name : "null",
                  "integer");
        return;
    }

    parse_str(siv, errp);

    if (!siv->ranges) {
        goto error;
    }

    if (!siv->cur_range) {
        siv->cur_range = QTAILQ_FIRST(siv->ranges);
        if (siv->cur_range) {
            siv->cur = siv->cur_range->start;
        } else {
            goto error;
        }
    }

    *obj = siv->cur;
    siv->cur++;
    return;

error:
    error_set(errp, QERR_INVALID_PARAMETER_VALUE, name,
              "an int64 value or range");
}

static void parse_type_size(Visitor *v, uint64_t *obj, const char *name,
                            Error **errp)
{
    StringInputVisitor *siv = DO_UPCAST(StringInputVisitor, visitor, v);
    Error *err = NULL;
    uint64_t val;

    if (siv->string) {
        parse_option_size(name, siv->string, &val, &err);
    } else {
        error_set(errp, QERR_INVALID_PARAMETER_TYPE, name ? name : "null",
                  "size");
        return;
    }
    if (err) {
        error_propagate(errp, err);
        return;
    }

    *obj = val;
}

static void parse_type_bool(Visitor *v, bool *obj, const char *name,
                            Error **errp)
{
    StringInputVisitor *siv = DO_UPCAST(StringInputVisitor, visitor, v);

    if (siv->string) {
        if (!strcasecmp(siv->string, "on") ||
            !strcasecmp(siv->string, "yes") ||
            !strcasecmp(siv->string, "true")) {
            *obj = true;
            return;
        }
        if (!strcasecmp(siv->string, "off") ||
            !strcasecmp(siv->string, "no") ||
            !strcasecmp(siv->string, "false")) {
            *obj = false;
            return;
        }
    }

    error_set(errp, QERR_INVALID_PARAMETER_TYPE, name ? name : "null",
              "boolean");
}

static void parse_type_str(Visitor *v, char **obj, const char *name,
                           Error **errp)
{
    StringInputVisitor *siv = DO_UPCAST(StringInputVisitor, visitor, v);
    if (siv->string) {
        *obj = g_strdup(siv->string);
    } else {
        error_set(errp, QERR_INVALID_PARAMETER_TYPE, name ? name : "null",
                  "string");
    }
}

static void parse_type_number(Visitor *v, double *obj, const char *name,
                              Error **errp)
{
    StringInputVisitor *siv = DO_UPCAST(StringInputVisitor, visitor, v);
    char *endp = (char *) siv->string;
    double val;

    errno = 0;
    if (siv->string) {
        val = strtod(siv->string, &endp);
    }
    if (!siv->string || errno || endp == siv->string || *endp) {
        error_set(errp, QERR_INVALID_PARAMETER_TYPE, name ? name : "null",
                  "number");
        return;
    }

    *obj = val;
}

static void parse_start_optional(Visitor *v, bool *present,
                                 const char *name, Error **errp)
{
    StringInputVisitor *siv = DO_UPCAST(StringInputVisitor, visitor, v);

    if (!siv->string) {
        *present = false;
        return;
    }

    *present = true;
}

Visitor *string_input_get_visitor(StringInputVisitor *v)
{
    return &v->visitor;
}

void string_input_visitor_cleanup(StringInputVisitor *v)
{
    SignedRange *r, *next;

    if (v->ranges) {
        QTAILQ_FOREACH_SAFE(r, v->ranges, entry, next) {
            QTAILQ_REMOVE(v->ranges, r, entry);
            g_free(r);
        }
        g_free(v->ranges);
    }

    g_free(v);
}

StringInputVisitor *string_input_visitor_new(const char *str)
{
    StringInputVisitor *v;

    v = g_malloc0(sizeof(*v));

    v->visitor.type_enum = input_type_enum;
    v->visitor.type_int = parse_type_int;
    v->visitor.type_size = parse_type_size;
    v->visitor.type_bool = parse_type_bool;
    v->visitor.type_str = parse_type_str;
    v->visitor.type_number = parse_type_number;
    v->visitor.start_list = start_list;
    v->visitor.next_list = next_list;
    v->visitor.end_list = end_list;
    v->visitor.start_optional = parse_start_optional;

    v->string = str;
    v->head = true;
    return v;
}

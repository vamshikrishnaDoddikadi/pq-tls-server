/**
 * @file json_helpers.c
 * @brief Minimal JSON tokenizer/parser and snprintf-based builder
 */

#include "json_helpers.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* ======================================================================== */
/* JSON Builder                                                              */
/* ======================================================================== */

static void jb_append(json_builder_t *jb, const char *s, size_t n) {
    if (jb->error || jb->len + n >= jb->cap) {
        jb->error = 1;
        return;
    }
    memcpy(jb->buf + jb->len, s, n);
    jb->len += n;
    jb->buf[jb->len] = '\0';
}

static void jb_append_str(json_builder_t *jb, const char *s) {
    jb_append(jb, s, strlen(s));
}

static void jb_maybe_comma(json_builder_t *jb) {
    if (jb->need_comma) {
        jb_append(jb, ",", 1);
    }
}

void jb_init(json_builder_t *jb, char *buf, size_t cap) {
    jb->buf = buf;
    jb->cap = cap;
    jb->len = 0;
    jb->depth = 0;
    jb->need_comma = 0;
    jb->error = 0;
    if (cap > 0) buf[0] = '\0';
}

void jb_object_start(json_builder_t *jb) {
    jb_maybe_comma(jb);
    jb_append(jb, "{", 1);
    jb->depth++;
    jb->need_comma = 0;
}

void jb_object_end(json_builder_t *jb) {
    jb_append(jb, "}", 1);
    jb->depth--;
    jb->need_comma = 1;
}

void jb_array_start(json_builder_t *jb) {
    jb_maybe_comma(jb);
    jb_append(jb, "[", 1);
    jb->depth++;
    jb->need_comma = 0;
}

void jb_array_end(json_builder_t *jb) {
    jb_append(jb, "]", 1);
    jb->depth--;
    jb->need_comma = 1;
}

void jb_key(json_builder_t *jb, const char *key) {
    jb_maybe_comma(jb);
    jb_append(jb, "\"", 1);
    /* Escape key */
    for (const char *p = key; *p; p++) {
        switch (*p) {
        case '"':  jb_append(jb, "\\\"", 2); break;
        case '\\': jb_append(jb, "\\\\", 2); break;
        case '\n': jb_append(jb, "\\n", 2);  break;
        case '\r': jb_append(jb, "\\r", 2);  break;
        case '\t': jb_append(jb, "\\t", 2);  break;
        default:   jb_append(jb, p, 1);      break;
        }
    }
    jb_append(jb, "\":", 2);
    jb->need_comma = 0;
}

void jb_val_str(json_builder_t *jb, const char *val) {
    jb_maybe_comma(jb);
    jb_append(jb, "\"", 1);
    if (val) {
        for (const char *p = val; *p; p++) {
            unsigned char ch = (unsigned char)*p;
            switch (*p) {
            case '"':  jb_append(jb, "\\\"", 2); break;
            case '\\': jb_append(jb, "\\\\", 2); break;
            case '\b': jb_append(jb, "\\b", 2);  break;
            case '\f': jb_append(jb, "\\f", 2);  break;
            case '\n': jb_append(jb, "\\n", 2);  break;
            case '\r': jb_append(jb, "\\r", 2);  break;
            case '\t': jb_append(jb, "\\t", 2);  break;
            default:
                if (ch < 0x20) {
                    char esc[8];
                    snprintf(esc, sizeof(esc), "\\u%04x", ch);
                    jb_append(jb, esc, 6);
                } else {
                    jb_append(jb, p, 1);
                }
                break;
            }
        }
    }
    jb_append(jb, "\"", 1);
    jb->need_comma = 1;
}

void jb_val_int(json_builder_t *jb, long val) {
    jb_maybe_comma(jb);
    char tmp[32];
    int n = snprintf(tmp, sizeof(tmp), "%ld", val);
    if (n < 0) { jb->error = 1; return; }
    jb_append(jb, tmp, (size_t)n);
    jb->need_comma = 1;
}

void jb_val_double(json_builder_t *jb, double val) {
    jb_maybe_comma(jb);
    char tmp[64];
    int n = snprintf(tmp, sizeof(tmp), "%.2f", val);
    if (n < 0) { jb->error = 1; return; }
    jb_append(jb, tmp, (size_t)n);
    jb->need_comma = 1;
}

void jb_val_bool(json_builder_t *jb, int val) {
    jb_maybe_comma(jb);
    if (val) jb_append_str(jb, "true");
    else     jb_append_str(jb, "false");
    jb->need_comma = 1;
}

void jb_val_null(json_builder_t *jb) {
    jb_maybe_comma(jb);
    jb_append_str(jb, "null");
    jb->need_comma = 1;
}

void jb_key_str(json_builder_t *jb, const char *key, const char *val) {
    jb_key(jb, key);
    jb_val_str(jb, val);
}

void jb_key_int(json_builder_t *jb, const char *key, long val) {
    jb_key(jb, key);
    jb_val_int(jb, val);
}

void jb_key_bool(json_builder_t *jb, const char *key, int val) {
    jb_key(jb, key);
    jb_val_bool(jb, val);
}

size_t jb_finish(json_builder_t *jb) {
    if (jb->error) return 0;
    return jb->len;
}

/* ======================================================================== */
/* JSON Token Parser                                                         */
/* ======================================================================== */

void jp_init(json_parser_t *jp, const char *json, size_t len) {
    jp->json = json;
    jp->pos = 0;
    jp->len = len;
    jp->type = JSON_TOK_NONE;
    jp->val_start = NULL;
    jp->val_len = 0;
}

static void jp_skip_ws(json_parser_t *jp) {
    while (jp->pos < jp->len && isspace((unsigned char)jp->json[jp->pos]))
        jp->pos++;
}

json_tok_type_t jp_next(json_parser_t *jp) {
    jp_skip_ws(jp);

    if (jp->pos >= jp->len) {
        jp->type = JSON_TOK_END;
        return jp->type;
    }

    char c = jp->json[jp->pos];

    switch (c) {
    case '{': jp->pos++; jp->type = JSON_TOK_OBJECT_START; return jp->type;
    case '}': jp->pos++; jp->type = JSON_TOK_OBJECT_END;   return jp->type;
    case '[': jp->pos++; jp->type = JSON_TOK_ARRAY_START;   return jp->type;
    case ']': jp->pos++; jp->type = JSON_TOK_ARRAY_END;     return jp->type;
    case ':': jp->pos++; jp->type = JSON_TOK_COLON;         return jp->type;
    case ',': jp->pos++; jp->type = JSON_TOK_COMMA;         return jp->type;

    case '"': {
        jp->pos++; /* skip opening quote */
        size_t start = jp->pos;
        while (jp->pos < jp->len) {
            if (jp->json[jp->pos] == '\\') {
                jp->pos += 2;
                if (jp->pos > jp->len) break;
                continue;
            }
            if (jp->json[jp->pos] == '"') break;
            jp->pos++;
        }
        jp->val_start = jp->json + start;
        jp->val_len = jp->pos - start;
        if (jp->pos < jp->len) jp->pos++; /* skip closing quote */
        jp->type = JSON_TOK_STRING;
        return jp->type;
    }

    case 't':
        if (jp->pos + 4 <= jp->len && strncmp(jp->json + jp->pos, "true", 4) == 0) {
            jp->val_start = jp->json + jp->pos;
            jp->val_len = 4;
            jp->pos += 4;
            jp->type = JSON_TOK_BOOL;
            return jp->type;
        }
        jp->type = JSON_TOK_ERROR;
        return jp->type;

    case 'f':
        if (jp->pos + 5 <= jp->len && strncmp(jp->json + jp->pos, "false", 5) == 0) {
            jp->val_start = jp->json + jp->pos;
            jp->val_len = 5;
            jp->pos += 5;
            jp->type = JSON_TOK_BOOL;
            return jp->type;
        }
        jp->type = JSON_TOK_ERROR;
        return jp->type;

    case 'n':
        if (jp->pos + 4 <= jp->len && strncmp(jp->json + jp->pos, "null", 4) == 0) {
            jp->val_start = jp->json + jp->pos;
            jp->val_len = 4;
            jp->pos += 4;
            jp->type = JSON_TOK_NULL;
            return jp->type;
        }
        jp->type = JSON_TOK_ERROR;
        return jp->type;

    default:
        if (c == '-' || (c >= '0' && c <= '9')) {
            size_t start = jp->pos;
            if (c == '-') jp->pos++;
            while (jp->pos < jp->len && (jp->json[jp->pos] >= '0' && jp->json[jp->pos] <= '9'))
                jp->pos++;
            if (jp->pos < jp->len && jp->json[jp->pos] == '.') {
                jp->pos++;
                while (jp->pos < jp->len && (jp->json[jp->pos] >= '0' && jp->json[jp->pos] <= '9'))
                    jp->pos++;
            }
            if (jp->pos < jp->len && (jp->json[jp->pos] == 'e' || jp->json[jp->pos] == 'E')) {
                jp->pos++;
                if (jp->pos < jp->len && (jp->json[jp->pos] == '+' || jp->json[jp->pos] == '-'))
                    jp->pos++;
                while (jp->pos < jp->len && (jp->json[jp->pos] >= '0' && jp->json[jp->pos] <= '9'))
                    jp->pos++;
            }
            jp->val_start = jp->json + start;
            jp->val_len = jp->pos - start;
            jp->type = JSON_TOK_NUMBER;
            return jp->type;
        }
        jp->type = JSON_TOK_ERROR;
        return jp->type;
    }
}

int jp_string_value(const json_parser_t *jp, char *buf, size_t buf_size) {
    if (jp->type != JSON_TOK_STRING || !buf || buf_size == 0) return -1;

    size_t j = 0;
    for (size_t i = 0; i < jp->val_len && j < buf_size - 1; i++) {
        if (jp->val_start[i] == '\\' && i + 1 < jp->val_len) {
            i++;
            switch (jp->val_start[i]) {
            case '"':  buf[j++] = '"';  break;
            case '\\': buf[j++] = '\\'; break;
            case 'n':  buf[j++] = '\n'; break;
            case 'r':  buf[j++] = '\r'; break;
            case 't':  buf[j++] = '\t'; break;
            case '/':  buf[j++] = '/';  break;
            default:   buf[j++] = jp->val_start[i]; break;
            }
        } else {
            buf[j++] = jp->val_start[i];
        }
    }
    buf[j] = '\0';
    return (int)j;
}

long jp_int_value(const json_parser_t *jp) {
    if (jp->type != JSON_TOK_NUMBER) return 0;
    char tmp[32];
    size_t n = jp->val_len < sizeof(tmp) - 1 ? jp->val_len : sizeof(tmp) - 1;
    memcpy(tmp, jp->val_start, n);
    tmp[n] = '\0';
    return strtol(tmp, NULL, 10);
}

int jp_bool_value(const json_parser_t *jp) {
    if (jp->type != JSON_TOK_BOOL) return 0;
    return (jp->val_len == 4 && jp->val_start[0] == 't') ? 1 : 0;
}

/* ======================================================================== */
/* High-level extraction helpers                                             */
/* ======================================================================== */

int json_extract_string(const char *json, const char *key, char *out, size_t out_size) {
    if (!json || !key || !out || out_size == 0) return -1;

    json_parser_t jp;
    jp_init(&jp, json, strlen(json));

    if (jp_next(&jp) != JSON_TOK_OBJECT_START) return -1;

    while (1) {
        json_tok_type_t t = jp_next(&jp);
        if (t == JSON_TOK_OBJECT_END || t == JSON_TOK_END || t == JSON_TOK_ERROR) break;
        if (t != JSON_TOK_STRING) continue;

        char kbuf[256];
        jp_string_value(&jp, kbuf, sizeof(kbuf));

        t = jp_next(&jp); /* colon */
        if (t != JSON_TOK_COLON) break;

        t = jp_next(&jp); /* value */
        if (strcmp(kbuf, key) == 0) {
            if (t == JSON_TOK_STRING) {
                jp_string_value(&jp, out, out_size);
                return 0;
            }
            return -1;
        }

        /* Skip value if it's a nested structure */
        if (t == JSON_TOK_OBJECT_START || t == JSON_TOK_ARRAY_START) {
            int depth = 1;
            while (depth > 0) {
                t = jp_next(&jp);
                if (t == JSON_TOK_OBJECT_START || t == JSON_TOK_ARRAY_START) depth++;
                else if (t == JSON_TOK_OBJECT_END || t == JSON_TOK_ARRAY_END) depth--;
                else if (t == JSON_TOK_END || t == JSON_TOK_ERROR) return -1;
            }
        }
    }
    return -1;
}

int json_extract_int(const char *json, const char *key, long *out) {
    if (!json || !key || !out) return -1;

    json_parser_t jp;
    jp_init(&jp, json, strlen(json));

    if (jp_next(&jp) != JSON_TOK_OBJECT_START) return -1;

    while (1) {
        json_tok_type_t t = jp_next(&jp);
        if (t == JSON_TOK_OBJECT_END || t == JSON_TOK_END || t == JSON_TOK_ERROR) break;
        if (t != JSON_TOK_STRING) continue;

        char kbuf[256];
        jp_string_value(&jp, kbuf, sizeof(kbuf));

        t = jp_next(&jp); /* colon */
        if (t != JSON_TOK_COLON) break;

        t = jp_next(&jp); /* value */
        if (strcmp(kbuf, key) == 0) {
            if (t == JSON_TOK_NUMBER) {
                *out = jp_int_value(&jp);
                return 0;
            }
            return -1;
        }

        if (t == JSON_TOK_OBJECT_START || t == JSON_TOK_ARRAY_START) {
            int depth = 1;
            while (depth > 0) {
                t = jp_next(&jp);
                if (t == JSON_TOK_OBJECT_START || t == JSON_TOK_ARRAY_START) depth++;
                else if (t == JSON_TOK_OBJECT_END || t == JSON_TOK_ARRAY_END) depth--;
                else if (t == JSON_TOK_END || t == JSON_TOK_ERROR) return -1;
            }
        }
    }
    return -1;
}

int json_extract_bool(const char *json, const char *key, int *out) {
    if (!json || !key || !out) return -1;

    json_parser_t jp;
    jp_init(&jp, json, strlen(json));

    if (jp_next(&jp) != JSON_TOK_OBJECT_START) return -1;

    while (1) {
        json_tok_type_t t = jp_next(&jp);
        if (t == JSON_TOK_OBJECT_END || t == JSON_TOK_END || t == JSON_TOK_ERROR) break;
        if (t != JSON_TOK_STRING) continue;

        char kbuf[256];
        jp_string_value(&jp, kbuf, sizeof(kbuf));

        t = jp_next(&jp);
        if (t != JSON_TOK_COLON) break;

        t = jp_next(&jp);
        if (strcmp(kbuf, key) == 0) {
            if (t == JSON_TOK_BOOL) {
                *out = jp_bool_value(&jp);
                return 0;
            }
            return -1;
        }

        if (t == JSON_TOK_OBJECT_START || t == JSON_TOK_ARRAY_START) {
            int depth = 1;
            while (depth > 0) {
                t = jp_next(&jp);
                if (t == JSON_TOK_OBJECT_START || t == JSON_TOK_ARRAY_START) depth++;
                else if (t == JSON_TOK_OBJECT_END || t == JSON_TOK_ARRAY_END) depth--;
                else if (t == JSON_TOK_END || t == JSON_TOK_ERROR) return -1;
            }
        }
    }
    return -1;
}

int json_extract_array(const char *json, const char *key, json_array_cb cb, void *ctx) {
    if (!json || !key || !cb) return -1;

    json_parser_t jp;
    jp_init(&jp, json, strlen(json));

    if (jp_next(&jp) != JSON_TOK_OBJECT_START) return -1;

    while (1) {
        json_tok_type_t t = jp_next(&jp);
        if (t == JSON_TOK_OBJECT_END || t == JSON_TOK_END || t == JSON_TOK_ERROR) break;
        if (t != JSON_TOK_STRING) continue;

        char kbuf[256];
        jp_string_value(&jp, kbuf, sizeof(kbuf));

        t = jp_next(&jp);
        if (t != JSON_TOK_COLON) break;

        if (strcmp(kbuf, key) == 0) {
            t = jp_next(&jp);
            if (t != JSON_TOK_ARRAY_START) return -1;

            int index = 0;
            while (1) {
                /* Find start of next element */
                size_t elem_start = jp.pos;
                jp_skip_ws(&jp);
                if (jp.pos < jp.len && jp.json[jp.pos] == ']') {
                    jp.pos++;
                    break;
                }
                if (jp.pos < jp.len && jp.json[jp.pos] == ',') {
                    jp.pos++;
                    elem_start = jp.pos;
                }

                /* Find end of element by tracking depth */
                t = jp_next(&jp);
                if (t == JSON_TOK_END || t == JSON_TOK_ERROR) return -1;
                if (t == JSON_TOK_ARRAY_END) break;

                size_t start = jp.val_start ? (size_t)(jp.val_start - jp.json) : elem_start;
                if (t == JSON_TOK_STRING) start--; /* include opening quote */

                if (t == JSON_TOK_OBJECT_START || t == JSON_TOK_ARRAY_START) {
                    start = jp.pos - 1;
                    int depth = 1;
                    while (depth > 0) {
                        t = jp_next(&jp);
                        if (t == JSON_TOK_OBJECT_START || t == JSON_TOK_ARRAY_START) depth++;
                        else if (t == JSON_TOK_OBJECT_END || t == JSON_TOK_ARRAY_END) depth--;
                        else if (t == JSON_TOK_END || t == JSON_TOK_ERROR) return -1;
                    }
                }

                size_t elem_len = jp.pos - start;
                if (cb(jp.json + start, elem_len, index, ctx) != 0) return -1;
                index++;
            }
            return 0;
        }

        /* Skip value */
        t = jp_next(&jp);
        if (t == JSON_TOK_OBJECT_START || t == JSON_TOK_ARRAY_START) {
            int depth = 1;
            while (depth > 0) {
                t = jp_next(&jp);
                if (t == JSON_TOK_OBJECT_START || t == JSON_TOK_ARRAY_START) depth++;
                else if (t == JSON_TOK_OBJECT_END || t == JSON_TOK_ARRAY_END) depth--;
                else if (t == JSON_TOK_END || t == JSON_TOK_ERROR) return -1;
            }
        }
    }
    return -1;
}

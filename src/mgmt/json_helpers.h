/**
 * @file json_helpers.h
 * @brief Minimal JSON tokenizer/parser and snprintf-based builder
 */

#ifndef PQ_JSON_HELPERS_H
#define PQ_JSON_HELPERS_H

#include <stddef.h>

/* ======================================================================== */
/* JSON Builder — snprintf-based, writes into a caller-supplied buffer      */
/* ======================================================================== */

typedef struct {
    char   *buf;
    size_t  cap;
    size_t  len;
    int     depth;
    int     need_comma;
    int     error;     /* set if buffer overflowed */
} json_builder_t;

void   jb_init(json_builder_t *jb, char *buf, size_t cap);
void   jb_object_start(json_builder_t *jb);
void   jb_object_end(json_builder_t *jb);
void   jb_array_start(json_builder_t *jb);
void   jb_array_end(json_builder_t *jb);
void   jb_key(json_builder_t *jb, const char *key);
void   jb_val_str(json_builder_t *jb, const char *val);
void   jb_val_int(json_builder_t *jb, long val);
void   jb_val_double(json_builder_t *jb, double val);
void   jb_val_bool(json_builder_t *jb, int val);
void   jb_val_null(json_builder_t *jb);
void   jb_key_str(json_builder_t *jb, const char *key, const char *val);
void   jb_key_int(json_builder_t *jb, const char *key, long val);
void   jb_key_bool(json_builder_t *jb, const char *key, int val);
size_t jb_finish(json_builder_t *jb);

/* ======================================================================== */
/* JSON Token Parser — minimal, read-only, no allocations                   */
/* ======================================================================== */

typedef enum {
    JSON_TOK_NONE,
    JSON_TOK_OBJECT_START,
    JSON_TOK_OBJECT_END,
    JSON_TOK_ARRAY_START,
    JSON_TOK_ARRAY_END,
    JSON_TOK_STRING,
    JSON_TOK_NUMBER,
    JSON_TOK_BOOL,
    JSON_TOK_NULL,
    JSON_TOK_COLON,
    JSON_TOK_COMMA,
    JSON_TOK_ERROR,
    JSON_TOK_END
} json_tok_type_t;

typedef struct {
    const char *json;
    size_t      pos;
    size_t      len;
    /* Current token */
    json_tok_type_t type;
    const char *val_start;
    size_t      val_len;
} json_parser_t;

void            jp_init(json_parser_t *jp, const char *json, size_t len);
json_tok_type_t jp_next(json_parser_t *jp);

/* Convenience: copy current string token value into buf (unescaped) */
int  jp_string_value(const json_parser_t *jp, char *buf, size_t buf_size);
long jp_int_value(const json_parser_t *jp);
int  jp_bool_value(const json_parser_t *jp);

/* Extract a string value for a key from a JSON object string */
int json_extract_string(const char *json, const char *key, char *out, size_t out_size);
int json_extract_int(const char *json, const char *key, long *out);
int json_extract_bool(const char *json, const char *key, int *out);

/* Extract array of objects — calls callback for each element */
typedef int (*json_array_cb)(const char *element_json, size_t len, int index, void *ctx);
int json_extract_array(const char *json, const char *key, json_array_cb cb, void *ctx);

#endif /* PQ_JSON_HELPERS_H */

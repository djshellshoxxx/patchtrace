/*
 * switchtables: lookup helpers that are dominated by switch statements.
 *
 * A small decoder toolbox in the style of an emulator or protocol analyser: HTTP status mapping, calendar helpers,
 * binary-format tag classifiers (TLV, PNG chunks, UTF-8, HRESULT, errno, IP protocols), a toy 8-bit ISA decoder and a
 * tokenizer automaton. Dense switches turn into jump tables or constant lookup tables once the optimiser runs, sparse
 * ones into compare chains, bit tests or binary search trees, and at -O0 everything stays a compare chain.
 * Freestanding C11: no libc, no mutable globals.
 */
#include <stddef.h>
#include <stdint.h>

#define ST_TLV_VARIABLE 0xFFu
#define ST_TLV_UNKNOWN 0xFEu
#define ST_IN_RANGE(v, lo, hi) ((v) >= (lo) && (v) <= (hi))
#define ST_FOURCC(a, b, c, d) \
    (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) | (uint32_t)(d))

enum st_status_class { ST_CLASS_INFO, ST_CLASS_OK, ST_CLASS_REDIRECT, ST_CLASS_CLIENT, ST_CLASS_SERVER, ST_CLASS_INVALID };
enum st_char_kind {
    ST_CC_OTHER, ST_CC_DIGIT, ST_CC_UPPER, ST_CC_LOWER, ST_CC_SPACE, ST_CC_PUNCT, ST_CC_CTRL, ST_CC_QUOTE, ST_CC_BACKSLASH
};
enum st_lex_state { ST_LEX_START, ST_LEX_IDENT, ST_LEX_NUMBER, ST_LEX_STRING, ST_LEX_ESCAPE, ST_LEX_PUNCT, ST_LEX_ERROR };
enum st_operand { ST_OPND_NONE, ST_OPND_REG, ST_OPND_IND, ST_OPND_DISP8, ST_OPND_DISP32, ST_OPND_SIB, ST_OPND_ABS };

/* ---- HTTP status mapping ------------------------------------------------------------------------------------ */

/* Coarse class of an HTTP status code (its hundreds digit). */
uint32_t st_status_class(uint32_t code) {
    switch (code / 100u) {
    case 1: return ST_CLASS_INFO;
    case 2: return ST_CLASS_OK;
    case 3: return ST_CLASS_REDIRECT;
    case 4: return ST_CLASS_CLIENT;
    case 5: return ST_CLASS_SERVER;
    default: return ST_CLASS_INVALID;
    }
}

/* Index into the reason-phrase table for the statuses an embedded server emits; 0 when unknown. */
uint32_t st_status_phrase(uint32_t status) {
    switch (status) {
    case 100: return 1;
    case 101: return 2;
    case 200: return 3;
    case 201: return 4;
    case 202: return 5;
    case 204: return 6;
    case 206: return 7;
    case 301: return 8;
    case 302: return 9;
    case 303: return 10;
    case 304: return 11;
    case 307: return 12;
    case 308: return 13;
    case 400: return 14;
    case 401: return 15;
    case 403: return 16;
    case 404: return 17;
    case 405: return 18;
    case 408: return 19;
    case 409: return 20;
    case 410: return 21;
    case 413: return 22;
    case 415: return 23;
    case 418: return 24;
    case 429: return 25;
    case 500: return 26;
    case 501: return 27;
    case 502: return 28;
    case 503: return 29;
    case 504: return 30;
    default: return 0;
    }
}

/* ---- calendar helpers --------------------------------------------------------------------------------------- */

/* Number of days in a Gregorian month; 0 for a month outside 1..12. */
uint32_t st_days_in_month(uint32_t year, uint32_t month) {
    switch (month) {
    case 1: case 3: case 5: case 7: case 8: case 10: case 12:
        return 31;
    case 4: case 6: case 9: case 11:
        return 30;
    case 2:
        if ((year % 4u == 0u && year % 100u != 0u) || year % 400u == 0u) {
            return 29;
        }
        return 28;
    default:
        return 0;
    }
}

/* 1-based day number inside the year, or 0 for an impossible date. */
uint32_t st_day_of_year(uint32_t year, uint32_t month, uint32_t day) {
    uint32_t total = 0;
    if (!ST_IN_RANGE(month, 1u, 12u) || !ST_IN_RANGE(day, 1u, st_days_in_month(year, month))) {
        return 0;
    }
    for (uint32_t m = 1; m < month; m++) {
        total += st_days_in_month(year, m);
    }
    return total + day;
}

/* Month term of the Sakamoto day-of-week formula. */
uint32_t st_month_offset(uint32_t month) {
    switch (month) {
    case 1: return 0;
    case 2: return 3;
    case 3: return 2;
    case 4: return 5;
    case 5: return 0;
    case 6: return 3;
    case 7: return 5;
    case 8: return 1;
    case 9: return 4;
    case 10: return 6;
    case 11: return 2;
    case 12: return 4;
    default: return 0;
    }
}

/* Day of week, 0 = Sunday. */
uint32_t st_weekday(uint32_t year, uint32_t month, uint32_t day) {
    uint32_t y = year;
    if (month < 3u) {
        y -= 1u;
    }
    return (y + y / 4u - y / 100u + y / 400u + st_month_offset(month) + day) % 7u;
}

/* Three-letter month name; the string literals land in .rdata and are reached through relocations. */
const char *st_month_abbrev(uint32_t month) {
    switch (month) {
    case 1: return "Jan";
    case 2: return "Feb";
    case 3: return "Mar";
    case 4: return "Apr";
    case 5: return "May";
    case 6: return "Jun";
    case 7: return "Jul";
    case 8: return "Aug";
    case 9: return "Sep";
    case 10: return "Oct";
    case 11: return "Nov";
    case 12: return "Dec";
    default: return "???";
    }
}

/* ---- binary format classifiers ------------------------------------------------------------------------------ */

/* Fixed payload length of a TLV tag, ST_TLV_VARIABLE when a length byte decides, ST_TLV_UNKNOWN otherwise. */
uint32_t st_tlv_payload_len(uint32_t tag) {
    switch (tag) {
    case 0x00: return 0;
    case 0x01: case 0x02: return 1;
    case 0x03: return 2;
    case 0x04: case 0x05: case 0x06: case 0x07: return 4;
    case 0x08: return 8;
    case 0x09: case 0x0A: return 16;
    case 0x0B: return 6;
    case 0x0C: return 3;
    case 0x10: case 0x11: case 0x12: return ST_TLV_VARIABLE;
    case 0x13: return 12;
    case 0x14: return 20;
    case 0x15: return 32;
    case 0x1E: case 0x1F: return ST_TLV_VARIABLE;
    default: return ST_TLV_UNKNOWN;
    }
}

/* Index of a known PNG chunk type (critical chunks first); 0 when the type is not recognised. */
uint32_t st_png_chunk_kind(uint32_t type) {
    switch (type) {
    case ST_FOURCC('I', 'H', 'D', 'R'): return 1;
    case ST_FOURCC('P', 'L', 'T', 'E'): return 2;
    case ST_FOURCC('I', 'D', 'A', 'T'): return 3;
    case ST_FOURCC('I', 'E', 'N', 'D'): return 4;
    case ST_FOURCC('t', 'R', 'N', 'S'): return 5;
    case ST_FOURCC('g', 'A', 'M', 'A'): return 6;
    case ST_FOURCC('c', 'H', 'R', 'M'): return 7;
    case ST_FOURCC('s', 'R', 'G', 'B'): return 8;
    case ST_FOURCC('i', 'C', 'C', 'P'): return 9;
    case ST_FOURCC('t', 'E', 'X', 't'): return 10;
    case ST_FOURCC('z', 'T', 'X', 't'): return 11;
    case ST_FOURCC('b', 'K', 'G', 'D'): return 12;
    case ST_FOURCC('p', 'H', 'Y', 's'): return 13;
    case ST_FOURCC('t', 'I', 'M', 'E'): return 14;
    default: return 0;
    }
}

/* Length of the UTF-8 sequence announced by a lead byte; 0 for continuation or invalid lead bytes. */
uint32_t st_utf8_seq_len(uint32_t lead) {
    switch ((lead & 0xFFu) >> 4) {
    case 0x0: case 0x1: case 0x2: case 0x3: case 0x4: case 0x5: case 0x6: case 0x7: return 1;
    case 0xC: case 0xD: return 2;
    case 0xE: return 3;
    case 0xF: return (lead & 0x08u) != 0u ? 0u : 4u;
    default: return 0;
    }
}

/* Severity bucket of the common COM HRESULT values; unknown failures and unknown successes get their own buckets. */
uint32_t st_hresult_severity(uint32_t hr) {
    switch (hr) {
    case 0x00000000u: return 0;
    case 0x00000001u: return 1;
    case 0x80004001u: return 2;
    case 0x80004002u: return 3;
    case 0x80004004u: return 4;
    case 0x80004005u: return 5;
    case 0x8000FFFFu: return 6;
    case 0x80070005u: return 7;
    case 0x80070006u: return 8;
    case 0x8007000Eu: return 9;
    case 0x80070057u: return 10;
    default: return (hr & 0x80000000u) != 0u ? 11u : 12u;
    }
}

/* Message-table index for a negative errno-style code (0 = success, 255 = unknown). */
uint32_t st_errno_text_id(int32_t err) {
    switch (err) {
    case 0: return 0;
    case -1: return 1;
    case -2: return 2;
    case -4: return 3;
    case -5: return 4;
    case -9: return 5;
    case -11: return 6;
    case -12: return 7;
    case -13: return 8;
    case -17: return 9;
    case -22: return 10;
    case -28: return 11;
    case -32: return 12;
    case -110: return 13;
    case -111: return 14;
    default: return 255;
    }
}

/* Kind of an IP protocol number: 1 ICMP, 2 IGMP, 3 TCP, 4 UDP, 5 tunnel, 6 GRE, 7 IPsec, 8 OSPF, 9 SCTP. */
uint32_t st_ip_proto_kind(uint32_t proto) {
    switch (proto) {
    case 1: case 58: return 1;
    case 2: return 2;
    case 6: return 3;
    case 17: return 4;
    case 41: return 5;
    case 47: return 6;
    case 50: case 51: return 7;
    case 89: return 8;
    case 132: return 9;
    default: return 0;
    }
}

/* ---- toy 8-bit ISA ------------------------------------------------------------------------------------------ */

/* Length in bytes of the instruction that starts with `op`; 0 marks an invalid opcode. */
uint32_t st_isa_length(uint32_t op) {
    switch ((op >> 4) & 0xFu) {
    case 0x0: return ((op & 0xFu) <= 5u) ? 1u : 0u;
    case 0x1: case 0x2: return 2u;
    case 0x3: case 0x5: case 0x7: return 3u;
    case 0x4: return 4u;
    case 0x6: return 2u;
    case 0xF:
        if ((op & 0xFu) == 0u) {
            return 1u;
        }
        return ((op & 0xFu) == 0xEu) ? 2u : 0u;
    default: return 0u;
    }
}

/* Cycle cost of an opcode; 0 for opcodes that do not exist. */
uint32_t st_isa_cycles(uint32_t op) {
    switch (op & 0xFFu) {
    case 0x00: case 0x01: case 0x04: case 0x05: return 1;
    case 0x02: return 4;
    case 0x03: return 6;
    case 0x10: case 0x11: return 3;
    case 0x12: case 0x13: return 2;
    case 0x20: case 0x21: case 0x22: case 0x23: case 0x24: case 0x25: return 2;
    case 0x26: return 8;
    case 0x27: return 16;
    case 0x30: case 0x31: case 0x32: case 0x33: case 0x34: case 0x35: return 3;
    case 0x36: return 9;
    case 0x37: return 17;
    case 0x40: case 0x41: case 0x42: case 0x43: case 0x44: case 0x45: return 4;
    case 0x46: return 10;
    case 0x47: return 18;
    case 0x50: case 0x51: return 5;
    case 0x52: case 0x53: return 6;
    case 0x60: case 0x61: case 0x62: case 0x63: case 0x64: case 0x65: case 0x66: return 3;
    case 0x67: return 4;
    case 0x70: return 3;
    case 0x71: return 6;
    case 0x72: return 4;
    case 0x73: return 7;
    case 0xF0: return 1;
    case 0xFE: return 2;
    default: return 0;
    }
}

/* Addressing kind encoded in a ModRM-style byte: 2-bit mode, 3-bit register field, 3-bit memory field. */
uint32_t st_operand_kind(uint32_t modrm) {
    uint32_t mode = (modrm >> 6) & 3u;
    uint32_t rm = modrm & 7u;
    switch (mode) {
    case 0:
        switch (rm) {
        case 4: return ST_OPND_SIB;
        case 5: return ST_OPND_ABS;
        default: return ST_OPND_IND;
        }
    case 1: return rm == 4u ? ST_OPND_SIB : ST_OPND_DISP8;
    case 2: return rm == 4u ? ST_OPND_SIB : ST_OPND_DISP32;
    default: return ST_OPND_REG;
    }
}

/* Saturating subtraction: a - b, or 0 when b is larger. */
uint32_t st_sat_sub(uint32_t a, uint32_t b) {
    return a > b ? a - b : 0u;
}

/* ALU of the toy machine: the operation index selects the expression. */
uint32_t st_alu(uint32_t op, uint32_t a, uint32_t b) {
    switch (op) {
    case 0: return a + b;
    case 1: return a - b;
    case 2: return a * b;
    case 3: return a & b;
    case 4: return a | b;
    case 5: return a ^ b;
    case 6: return a << (b & 31u);
    case 7: return a >> (b & 31u);
    case 8: return a < b ? a : b;
    case 9: return a > b ? a : b;
    case 10: return (a & b) + ((a ^ b) >> 1);
    case 11: return a > b ? a - b : b - a;
    case 12: return (a << (b & 31u)) | (a >> ((32u - b) & 31u));
    case 13: return st_sat_sub(a, b);
    default: return 0;
    }
}

/* ---- text scanning ------------------------------------------------------------------------------------------ */

/* Character class used by the tokenizer. */
uint32_t st_char_class(uint32_t c) {
    switch (c) {
    case '0': case '1': case '2': case '3': case '4': case '5': case '6': case '7': case '8': case '9':
        return ST_CC_DIGIT;
    case 'A': case 'B': case 'C': case 'D': case 'E': case 'F': case 'G': case 'H': case 'I': case 'J':
    case 'K': case 'L': case 'M': case 'N': case 'O': case 'P': case 'Q': case 'R': case 'S': case 'T':
    case 'U': case 'V': case 'W': case 'X': case 'Y': case 'Z':
        return ST_CC_UPPER;
    case 'a': case 'b': case 'c': case 'd': case 'e': case 'f': case 'g': case 'h': case 'i': case 'j':
    case 'k': case 'l': case 'm': case 'n': case 'o': case 'p': case 'q': case 'r': case 's': case 't':
    case 'u': case 'v': case 'w': case 'x': case 'y': case 'z':
        return ST_CC_LOWER;
    case ' ': case '\t': case '\n': case '\v': case '\f': case '\r':
        return ST_CC_SPACE;
    case '"': return ST_CC_QUOTE;
    case '\\': return ST_CC_BACKSLASH;
    case '!': case '#': case '$': case '%': case '&': case '\'': case '(': case ')': case '*': case '+':
    case ',': case '-': case '.': case '/': case ':': case ';': case '<': case '=': case '>': case '?':
    case '@': case '[': case ']': case '^': case '_': case '`': case '{': case '|': case '}': case '~':
        return ST_CC_PUNCT;
    default:
        return (c < 32u || c == 127u) ? ST_CC_CTRL : ST_CC_OTHER;
    }
}

/* One step of the tokenizer automaton; `cls` is an st_char_class() value and `state` an st_lex_state. */
uint32_t st_lex_step(uint32_t state, uint32_t cls) {
    switch (state) {
    case ST_LEX_START:
    case ST_LEX_PUNCT:
        switch (cls) {
        case ST_CC_UPPER: case ST_CC_LOWER: return ST_LEX_IDENT;
        case ST_CC_DIGIT: return ST_LEX_NUMBER;
        case ST_CC_SPACE: return ST_LEX_START;
        case ST_CC_QUOTE: return ST_LEX_STRING;
        case ST_CC_PUNCT: case ST_CC_BACKSLASH: return ST_LEX_PUNCT;
        default: return ST_LEX_ERROR;
        }
    case ST_LEX_IDENT:
        switch (cls) {
        case ST_CC_UPPER: case ST_CC_LOWER: case ST_CC_DIGIT: return ST_LEX_IDENT;
        default: return ST_LEX_START;
        }
    case ST_LEX_NUMBER:
        return cls == ST_CC_DIGIT ? ST_LEX_NUMBER : ST_LEX_START;
    case ST_LEX_STRING:
        switch (cls) {
        case ST_CC_QUOTE: return ST_LEX_START;
        case ST_CC_BACKSLASH: return ST_LEX_ESCAPE;
        case ST_CC_CTRL: return ST_LEX_ERROR;
        default: return ST_LEX_STRING;
        }
    case ST_LEX_ESCAPE:
        return cls == ST_CC_CTRL ? ST_LEX_ERROR : ST_LEX_STRING;
    default:
        return ST_LEX_ERROR;
    }
}

/* 24-bit RGB value of the 16-colour text-mode palette. */
uint32_t st_palette_rgb(uint32_t idx) {
    switch (idx & 15u) {
    case 0: return 0x000000u;
    case 1: return 0x0000AAu;
    case 2: return 0x00AA00u;
    case 3: return 0x00AAAAu;
    case 4: return 0xAA0000u;
    case 5: return 0xAA00AAu;
    case 6: return 0xAA5500u;
    case 7: return 0xAAAAAAu;
    case 8: return 0x555555u;
    case 9: return 0x5555FFu;
    case 10: return 0x55FF55u;
    case 11: return 0x55FFFFu;
    case 12: return 0xFF5555u;
    case 13: return 0xFF55FFu;
    case 14: return 0xFFFF55u;
    default: return 0xFFFFFFu;
    }
}

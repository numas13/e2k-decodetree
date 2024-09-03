#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include "e2k.h"

#define GEN_SM      1
#define GEN_MAS     1
#define GEN_OBSOLETE_INSN 0

static void print_header(const char *fmt, ...) {
    va_list ap;
    printf("######################################################################\n");
    printf("# ");
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    printf("######################################################################\n");
    printf("\n");
}

static void print_fixed_bits(int size, uint32_t value, uint32_t mask, uint32_t ignore) {
    for (int i = size; i--;) {
        if ((ignore >> i) & 1) {
            putchar('-');
        } else if ((mask >> i) & 1) {
            putchar((value >> i) & 1 ? '1' : '0');
        } else {
            putchar('.');
        }
    }
}

static int channels_mask(const struct al_opcode *p, int version) {
    int ret = 0;
    for (int i = 0; i < 6; ++i) {
        if (p->version[i] == version) {
            ret |= 1 << i;
        }
    }
    return ret;
}

static void print_channels(int chan) {
    int c0 = chan & 7;
    int c1 = (chan >> 3);

    if (c0 == c1) {
        // symmetric
        const char *s = NULL;
        switch (c0) {
        case 0b001: s = "00"; break;
        case 0b010: s = "01"; break;
        case 0b100: s = "10"; break;
        case 0b011: s = "0-"; break;
        case 0b101: s = "-0"; break;
        case 0b111: s = "--"; break;
        }
        printf("-%s", s);
    } else {
        // not symmetric
        switch (chan) {
        case 0b000001: printf("000"); break;
        case 0b000010: printf("001"); break;
        case 0b000011: printf("00-"); break;
        case 0b000100: printf("010"); break;
        case 0b001000: printf("100"); break;
        case 0b100000: printf("110"); break;
        default:
            printf("TODO ");
            print_fixed_bits(6, chan, 0x3f, 0);
        }
    }
}

#if GEN_MAS
static int mas_ignore(const struct al_format_info *f) {
    for (const char *s = f->operands; *s; ++s) {
        if (*s == 'm') {
            return 0;
        }
    }
    return 0x7f;
}
#endif

int main(int argc, char *argv[]) {
    const struct al_format_info *f;

    printf("# SPDX-License-Identifier: LGPL-3.0-only\n");
    printf("# SPDX-FileCopyrightText: 2024 Denis Drakhnia <numas13@gmail.com>\n");

    printf("\n");
    printf("# Automatically-generated. Manual editing required. :(\n");
#if !GEN_SM
    printf("#  no sm field\n");
#endif
#if !GEN_MAS
    printf("#  no mas field\n");
#endif
#if !GEN_OBSOLETE_INSN
    printf("#  obsolete instructions are commented (not_vN condition)\n");
#endif

    printf("\n");
    print_header("Fields");
    printf("%%dst         0:8\n");
    printf("%%dst_preg    0:5\n");
    printf("%%src4        0:8\n");
    printf("%%src2        8:8\n");
    printf("%%src1        16:8\n");
#if GEN_SM
    printf("%%sm          31:1\n");
#endif
    printf("%%src3        32:8\n");
    printf("%%wbs         16:8 !function=ex_lshift_2\n");
    printf("%%table       40:1 24:7\n");
    printf("%%aalit       8:2\n");
    printf("%%aau         10:2\n");
    printf("%%aainc       10:1\n");
    printf("%%aas         11:1\n");
    printf("%%aaincr      12:3\n");
    printf("%%aaindex     15:4\n");
    printf("%%aad         19:5\n");
#if GEN_MAS
    printf("%%mas         51:7\n");
#endif

    printf("\n");
    print_header("Argument sets");

    for (int i = 0; i < ALF_MAX; ++i) {
        f = &al_format_info[i];
        printf("&%-19s", f->name);
#if GEN_SM
        printf(" sm");
#endif
        for (const char *s = f->operands; *s; ++s) {
            switch (*s) {
            case 'D':
            case 'P': // pred reg dst
            case 'S': // state reg dst
                printf(" dst");
                break;
            case '1':
            case '2':
            case '3':
            case '4':
                printf(" src%c", *s);
                break;
            case 'L': // src3 or literal
                printf(" src3");
                break;
            case 'm':
#if GEN_MAS
                printf(" mas");
#endif
                break;
            case 'w': // src1
                printf(" wbs");
                break;
            case 's':
                printf(" sreg");
                break;
            case 'i':
                printf(" imm");
                break;
            case 'a':
                printf(" aad");
                break;
            case 'A':
                printf(" aaindex");
                printf(" aaincr aas aainc"); // for aaincr instruction...
                break;
            case 'l':
                printf(" aalit");
                break;
            case 't':
                printf(" table");
                break;
            case 'U': // aau register write
            case 'u': // aau register read
                printf(" aau");
                printf(" aad");
                printf(" aaindex");
                printf(" aaincr");
                break;
            case 'p': // merge predicate
            case 'c': // ct cond
            case '?': // predicate
            case ',':
                break;
            default:
                printf(" %c_todo", *s);
                break;
            }
        }
        printf("\n");
    }

    printf("\n");
    print_header("Formats");

    for (int i = 0; i < ALF_MAX; ++i) {
        f = &al_format_info[i];
        printf("@%-19s", f->name);
#if GEN_MAS
        printf(" ");
        print_fixed_bits(7, 0, 0, mas_ignore(f));
#endif
        printf(" ");
        print_fixed_bits(3, 0, 0, 0);
        printf(" ");
        print_fixed_bits(16, 0, 0, f->ales_ignore);
        printf(" ");
        print_fixed_bits(32, 0, 0, 0);
        printf(" &%-16s", f->name);
#if GEN_SM
        printf(" %%sm");
#endif
        for (const char *s = f->operands; *s; ++s) {
            switch (*s) {
            case 'D':
            case 'S': // state reg dst
                printf(" %%dst");
                break;
            case 'P': // pred reg dst
                printf(" dst=%%dst_preg");
                break;
            case '1':
            case '2':
            case '3':
            case '4':
                printf(" %%src%c", *s);
                break;
            case 'L': // src3 or literal
                printf(" %%src3");
                break;
            case 'm':
#if GEN_MAS
                printf(" %%mas");
#endif
                break;
            case 'w': // src1
                printf(" %%wbs");
                break;
            case 's':
                printf(" sreg=%%src1");
                break;
            case 'i':
                printf(" imm=%%src3");
                break;
            case 'a':
                printf(" %%aad");
                break;
            case 'A':
                printf(" %%aaindex");
                printf(" %%aaincr %%aas %%aainc"); // for aaincr instruction...
                break;
            case 'l':
                printf(" %%aalit");
                break;
            case 't':
                printf(" %%table");
                break;
            case 'U': // aau register write
            case 'u': // aau register read
                printf(" %%aau");
                printf(" %%aad");
                printf(" %%aaindex");
                printf(" %%aaincr");
                break;
            case 'p': // merge predicate
            case 'c': // ct cond
            case '?': // predicate
            case ',':
                break;
            default:
                printf(" %c_todo", *s);
                break;
            }
        }
        printf("\n");
    }

    printf("\n");
    print_header("Patterns");
    printf("# Channel encodings:\n");
    printf("#   000 alc0\n");
    printf("#   001 alc1\n");
    printf("#   010 alc2\n");
    printf("#   100 alc3\n");
    printf("#   101 alc4\n");
    printf("#   110 alc5\n");
    printf("#\n");
    printf("#   -00 alc0 or alc3\n");
    printf("#   -01 alc1 or alc4\n");
    printf("#   -10 alc2 or alc5\n");
    printf("#\n");
    printf("#   --0 alc0, alc2, alc3 or alc5\n");
    printf("#   -0- alc0, alc1, alc3 or alc4\n");
    printf("#\n");
    printf("#   --- any alc\n");

    bool group = false;
    for (int isa = 1; isa < 8; ++isa) {
        const struct al_opcode *p = al_opcodes;

        printf("\n");
        print_header("elbrus-v%d", isa);

        for (; p->name; ++p) {
            bool cond = false;
            int channels = channels_mask(p, isa);

            if (channels == 0) {
                continue;
            }

            f = &al_format_info[p->format];
            if ((p->flags & AF_ALIAS) && !group) {
                printf("{\n");
                group = true;
            }

            int width = 20;
#if !GEN_OBSOLETE_INSN
            if (p->flags & (AF_REMOVED_IN_V2 | AF_REMOVED_IN_V3)) {
                printf("#");
                width -= 1;
            }
#endif
            if (group) {
                printf("  ");
                width -= 2;
            }
            printf("%-*s", width, p->name);
#if GEN_MAS
            printf(" ");
            print_fixed_bits(7, 0, 0, mas_ignore(f));
#endif
            printf(" ");
            print_channels(channels);
            printf(" ");
            if (channels == 0b100100 && (p->flags & AF_EXPLICIT_ALES25)) {
                print_fixed_bits(16, 0x02c0, 0xffff, 0);
            } else if (channels == 0b001001 && (p->flags & AF_ALT_ALES03)) {
                print_fixed_bits(16, 0x02c0, f->ales_mask, f->ales_ignore);
            } else {
                print_fixed_bits(16, p->ales, f->ales_mask, f->ales_ignore);
            }
            printf(" ");
            print_fixed_bits(32, p->als, f->als_mask, 0);
            printf(" @%s", f->name);

            if (isa > 1) {
                cond = true;
                printf(" ? v%d", isa);
            } else if (p->flags & (AF_REMOVED_IN_V2 | AF_REMOVED_IN_V3)) {
                int ver = p->flags & AF_REMOVED_IN_V2 ? 2 : 3;
                cond = true;
                printf(" ? not_v%d", ver);
            }

            if (p->flags & AF_ALIAS) {
                if (!cond) {
                    printf(" ?");
                }
                printf(" alias");
            }

            printf("\n");

            if (!(p->flags & AF_ALIAS) && group) {
                printf("}\n");
                group = false;
            }
        }
    }

    return EXIT_SUCCESS;
}

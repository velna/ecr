/*
 * ecr_getopt.c
 *
 *  Created on: May 21, 2015
 *      Author: velna
 */

#include "config.h"
#include "ecr_getopt.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define _(x) x

static void ecr_exchange(char **argv, ecr_getopt_data_t *d) {
    int bottom = d->first_nonopt;
    int middle = d->last_nonopt;
    int top = d->optind;
    char *tem;

    /* Exchange the shorter segment with the far end of the longer segment.
     That puts the shorter segment into the right place.
     It leaves the longer segment in the right place overall,
     but it consists of two parts that need to be swapped next.  */

#if defined USE_NONOPTION_FLAGS
    /* First make sure the handling of the `__getopt_nonoption_flags'
     string can work normally.  Our top argument must be in the range
     of the string.  */
    if (d->__nonoption_flags_len > 0 && top >= d->__nonoption_flags_max_len)
    {
        /* We must extend the array.  The user plays games with us and
         presents new arguments.  */
        char *new_str = malloc (top + 1);
        if (new_str == NULL)
        d->__nonoption_flags_len = d->__nonoption_flags_max_len = 0;
        else
        {
            memset (__mempcpy (new_str, __getopt_nonoption_flags,
                            d->__nonoption_flags_max_len),
                    '\0', top + 1 - d->__nonoption_flags_max_len);
            d->__nonoption_flags_max_len = top + 1;
            __getopt_nonoption_flags = new_str;
        }
    }
#endif

    while (top > middle && middle > bottom) {
        if (top - middle > middle - bottom) {
            /* Bottom segment is the short one.  */
            int len = middle - bottom;
            int i;

            /* Swap it with the top part of the top segment.  */
            for (i = 0; i < len; i++) {
                tem = argv[bottom + i];
                argv[bottom + i] = argv[top - (middle - bottom) + i];
                argv[top - (middle - bottom) + i] = tem;
            }
            /* Exclude the moved bottom segment from further swapping.  */
            top -= len;
        } else {
            /* Top segment is the short one.  */
            int len = top - middle;
            int i;

            /* Swap it with the bottom part of the bottom segment.  */
            for (i = 0; i < len; i++) {
                tem = argv[bottom + i];
                argv[bottom + i] = argv[middle + i];
                argv[middle + i] = tem;
            }
            /* Exclude the moved top segment from further swapping.  */
            bottom += len;
        }
    }

    /* Update records for the slots the non-options now occupy.  */

    d->first_nonopt += (d->optind - d->last_nonopt);
    d->last_nonopt = d->optind;
}

static const char * ecr_getopt_initialize(int argc, char * const *argv, const char *optstring, ecr_getopt_data_t *d,
        int posixly_correct) {
    d->first_nonopt = d->last_nonopt = d->optind;

    d->nextchar = NULL;

    d->posixly_correct = posixly_correct | !!getenv("POSIXLY_CORRECT");

    /* Determine how to handle the ordering of options and nonoptions.  */

    if (optstring[0] == '-') {
        d->ordering = RETURN_IN_ORDER;
        ++optstring;
    } else if (optstring[0] == '+') {
        d->ordering = REQUIRE_ORDER;
        ++optstring;
    } else if (d->posixly_correct)
        d->ordering = REQUIRE_ORDER;
    else
        d->ordering = PERMUTE;

#if defined USE_NONOPTION_FLAGS
    if (!d->posixly_correct
            && argc == libc_argc && argv == libc_argv)
    {
        if (d->nonoption_flags_max_len == 0)
        {
            if (getopt_nonoption_flags == NULL
                    || getopt_nonoption_flags[0] == '\0')
            d->nonoption_flags_max_len = -1;
            else
            {
                const char *orig_str = getopt_nonoption_flags;
                int len = d->nonoption_flags_max_len = strlen (orig_str);
                if (d->nonoption_flags_max_len < argc)
                d->nonoption_flags_max_len = argc;
                getopt_nonoption_flags =
                (char *) malloc (d->nonoption_flags_max_len);
                if (getopt_nonoption_flags == NULL)
                d->nonoption_flags_max_len = -1;
                else
                memset (mempcpy (getopt_nonoption_flags, orig_str, len),
                        '\0', d->nonoption_flags_max_len - len);
            }
        }
        d->nonoption_flags_len = d->nonoption_flags_max_len;
    }
    else
    d->nonoption_flags_len = 0;
#endif

    return optstring;
}

static int ecr_getopt_internal_r(int argc, char * const *argv, const char *optstring, const ecr_option_t *longopts,
        int *longind, int long_only, ecr_getopt_data_t *d, int posixly_correct) {
    int print_errors = d->opterr;

    if (argc < 1)
        return -1;

    d->optarg = NULL;

    if (d->optind == 0 || !d->initialized) {
        if (d->optind == 0)
            d->optind = 1; /* Don't scan ARGV[0], the program name.  */
        optstring = ecr_getopt_initialize(argc, argv, optstring, d, posixly_correct);
        d->initialized = 1;
    } else if (optstring[0] == '-' || optstring[0] == '+')
        optstring++;
    if (optstring[0] == ':')
        print_errors = 0;

    /* Test whether ARGV[optind] points to a non-option argument.
     Either it does not have option syntax, or there is an environment flag
     from the shell indicating it is not an option.  The later information
     is only used when the used in the GNU libc.  */
#if defined USE_NONOPTION_FLAGS
# define NONOPTION_P (argv[d->optind][0] != '-' || argv[d->optind][1] == '\0' \
              || (d->optind < d->nonoption_flags_len            \
              && getopt_nonoption_flags[d->optind] == '1'))
#else
# define NONOPTION_P (argv[d->optind][0] != '-' || argv[d->optind][1] == '\0')
#endif

    if (d->nextchar == NULL || *d->nextchar == '\0') {
        /* Advance to the next ARGV-element.  */

        /* Give FIRST_NONOPT & LAST_NONOPT rational values if OPTIND has been
         moved back by the user (who may also have changed the arguments).  */
        if (d->last_nonopt > d->optind)
            d->last_nonopt = d->optind;
        if (d->first_nonopt > d->optind)
            d->first_nonopt = d->optind;

        if (d->ordering == PERMUTE) {
            /* If we have just processed some options following some non-options,
             exchange them so that the options come first.  */

            if (d->first_nonopt != d->last_nonopt && d->last_nonopt != d->optind)
                ecr_exchange((char **) argv, d);
            else if (d->last_nonopt != d->optind)
                d->first_nonopt = d->optind;

            /* Skip any additional non-options
             and extend the range of non-options previously skipped.  */

            while (d->optind < argc && NONOPTION_P)
                d->optind++;
            d->last_nonopt = d->optind;
        }

        /* The special ARGV-element `--' means premature end of options.
         Skip it like a null option,
         then exchange with previous non-options as if it were an option,
         then skip everything else like a non-option.  */

        if (d->optind != argc && !strcmp(argv[d->optind], "--")) {
            d->optind++;

            if (d->first_nonopt != d->last_nonopt && d->last_nonopt != d->optind)
                ecr_exchange((char **) argv, d);
            else if (d->first_nonopt == d->last_nonopt)
                d->first_nonopt = d->optind;
            d->last_nonopt = argc;

            d->optind = argc;
        }

        /* If we have done all the ARGV-elements, stop the scan
         and back over any non-options that we skipped and permuted.  */

        if (d->optind == argc) {
            /* Set the next-arg-index to point at the non-options
             that we previously skipped, so the caller will digest them.  */
            if (d->first_nonopt != d->last_nonopt)
                d->optind = d->first_nonopt;
            return -1;
        }

        /* If we have come to a non-option and did not permute it,
         either stop the scan or describe it to the caller and pass it by.  */

        if (NONOPTION_P) {
            if (d->ordering == REQUIRE_ORDER)
                return -1;
            d->optarg = argv[d->optind++];
            return 1;
        }

        /* We have found another option-ARGV-element.
         Skip the initial punctuation.  */

        d->nextchar = (argv[d->optind] + 1 + (longopts != NULL && argv[d->optind][1] == '-'));
    }

    /* Decode the current option-ARGV-element.  */

    /* Check whether the ARGV-element is a long option.

     If long_only and the ARGV-element has the form "-f", where f is
     a valid short option, don't consider it an abbreviated form of
     a long option that starts with f.  Otherwise there would be no
     way to give the -f short option.

     On the other hand, if there's a long option "fubar" and
     the ARGV-element is "-fu", do consider that an abbreviation of
     the long option, just like "--fu", and not "-f" with arg "u".

     This distinction seems to be the most useful approach.  */

    if (longopts != NULL
            && (argv[d->optind][1] == '-'
                    || (long_only && (argv[d->optind][2] || !strchr(optstring, argv[d->optind][1]))))) {
        char *nameend;
        unsigned int namelen;
        const ecr_option_t *p;
        const ecr_option_t *pfound = NULL;
        struct option_list {
            const ecr_option_t *p;
            struct option_list *next;
        }*ambig_list = NULL;
        int exact = 0;
        int indfound = -1;
        int option_index;

        for (nameend = d->nextchar; *nameend && *nameend != '='; nameend++)
            /* Do nothing.  */;
        namelen = nameend - d->nextchar;

        /* Test all long options for either exact match
         or abbreviated matches.  */
        for (p = longopts, option_index = 0; p->name; p++, option_index++)
            if (!strncmp(p->name, d->nextchar, namelen)) {
                if (namelen == (unsigned int) strlen(p->name)) {
                    /* Exact match found.  */
                    pfound = p;
                    indfound = option_index;
                    exact = 1;
                    break;
                } else if (pfound == NULL) {
                    /* First nonexact match found.  */
                    pfound = p;
                    indfound = option_index;
                } else if (long_only || pfound->has_arg != p->has_arg || pfound->flag != p->flag
                        || pfound->val != p->val) {
                    /* Second or later nonexact match found.  */
                    struct option_list *newp = alloca(sizeof(*newp));
                    newp->p = p;
                    newp->next = ambig_list;
                    ambig_list = newp;
                }
            }

        if (ambig_list != NULL && !exact) {
            if (print_errors) {
                struct option_list first;
                first.p = pfound;
                first.next = ambig_list;
                ambig_list = &first;

                char *buf = NULL;
                size_t buflen = 0;

                FILE *fp = open_memstream(&buf, &buflen);
                if (fp != NULL) {
                    fprintf(fp, "%s: option '%s' is ambiguous; possibilities:", argv[0], argv[d->optind]);

                    do {
                        fprintf(fp, " '--%s'", ambig_list->p->name);
                        ambig_list = ambig_list->next;
                    } while (ambig_list != NULL);

                    fputc_unlocked('\n', fp);

                    if (fclose(fp) != EOF) {
                        fprintf(stderr, "%s", buf);
                        free(buf);
                    }
                }
            }
            d->nextchar += strlen(d->nextchar);
            d->optind++;
            d->optopt = 0;
            return '?';
        }

        if (pfound != NULL) {
            option_index = indfound;
            d->optind++;
            if (*nameend) {
                /* Don't test has_arg with >, because some C compilers don't
                 allow it to be used on enums.  */
                if (pfound->has_arg)
                    d->optarg = nameend + 1;
                else {
                    if (print_errors) {
                        char *buf;
                        int n;

                        if (argv[d->optind - 1][1] == '-') {
                            /* --option */
                            n = __asprintf(&buf, "\
%s: option '--%s' doesn't allow an argument\n", argv[0],
                                    pfound->name);
                        } else {
                            /* +option or -option */
                            n = __asprintf(&buf, "\
%s: option '%c%s' doesn't allow an argument\n", argv[0],
                                    argv[d->optind - 1][0], pfound->name);
                        }

                        if (n >= 0) {
                            fprintf(stderr, "%s", buf);
                            free(buf);
                        }
                    }

                    d->nextchar += strlen(d->nextchar);

                    d->optopt = pfound->val;
                    return '?';
                }
            } else if (pfound->has_arg == 1) {
                if (d->optind < argc)
                    d->optarg = argv[d->optind++];
                else {
                    if (print_errors) {
                        char *buf;

                        if (__asprintf(&buf, _("\
%s: option '--%s' requires an argument\n"), argv[0], pfound->name)
                                >= 0) {
                            fprintf(stderr, "%s", buf);
                            free(buf);
                        }
                    }
                    d->nextchar += strlen(d->nextchar);
                    d->optopt = pfound->val;
                    return optstring[0] == ':' ? ':' : '?';
                }
            }
            d->nextchar += strlen(d->nextchar);
            if (longind != NULL)
                *longind = option_index;
            if (pfound->flag) {
                *(pfound->flag) = pfound->val;
                return 0;
            }
            return pfound->val;
        }

        /* Can't find it as a long option.  If this is not getopt_long_only,
         or the option starts with '--' or is not a valid short
         option, then it's an error.
         Otherwise interpret it as a short option.  */
        if (!long_only || argv[d->optind][1] == '-' || strchr(optstring, *d->nextchar) == NULL) {
            if (print_errors) {
                char *buf;
                int n;

                if (argv[d->optind][1] == '-') {
                    /* --option */
                    n = __asprintf(&buf, _("%s: unrecognized option '--%s'\n"), argv[0], d->nextchar);
                } else {
                    /* +option or -option */
                    n = __asprintf(&buf, _("%s: unrecognized option '%c%s'\n"), argv[0], argv[d->optind][0],
                            d->nextchar);
                }

                if (n >= 0) {
                    fprintf(stderr, "%s", buf);
                    free(buf);
                }
            }
            d->nextchar = (char *) "";
            d->optind++;
            d->optopt = 0;
            return '?';
        }
    }

    /* Look at and handle the next short option-character.  */

    {
        char c = *d->nextchar++;
        char *temp = strchr(optstring, c);

        /* Increment `optind' when we start to process its last character.  */
        if (*d->nextchar == '\0')
            ++d->optind;

        if (temp == NULL || c == ':' || c == ';') {
            if (print_errors) {
                char *buf;
                int n;

                n = __asprintf(&buf, _("%s: invalid option -- '%c'\n"), argv[0], c);

                if (n >= 0) {
                    fprintf(stderr, "%s", buf);
                    free(buf);
                }
            }
            d->optopt = c;
            return '?';
        }
        /* Convenience. Treat POSIX -W foo same as long option --foo */
        if (temp[0] == 'W' && temp[1] == ';') {
            if (longopts == NULL)
                goto no_longs;

            char *nameend;
            const ecr_option_t *p;
            const ecr_option_t *pfound = NULL;
            int exact = 0;
            int ambig = 0;
            int indfound = 0;
            int option_index;

            /* This is an option that requires an argument.  */
            if (*d->nextchar != '\0') {
                d->optarg = d->nextchar;
                /* If we end this ARGV-element by taking the rest as an arg,
                 we must advance to the next element now.  */
                d->optind++;
            } else if (d->optind == argc) {
                if (print_errors) {
                    char *buf;

                    if (__asprintf(&buf, _("%s: option requires an argument -- '%c'\n"), argv[0], c) >= 0) {
                        fprintf(stderr, "%s", buf);
                        free(buf);
                    }
                }
                d->optopt = c;
                if (optstring[0] == ':')
                    c = ':';
                else
                    c = '?';
                return c;
            } else
                /* We already incremented `d->optind' once;
                 increment it again when taking next ARGV-elt as argument.  */
                d->optarg = argv[d->optind++];

            /* optarg is now the argument, see if it's in the
             table of longopts.  */

            for (d->nextchar = nameend = d->optarg; *nameend && *nameend != '='; nameend++)
                /* Do nothing.  */;

            /* Test all long options for either exact match
             or abbreviated matches.  */
            for (p = longopts, option_index = 0; p->name; p++, option_index++)
                if (!strncmp(p->name, d->nextchar, nameend - d->nextchar)) {
                    if ((unsigned int) (nameend - d->nextchar) == strlen(p->name)) {
                        /* Exact match found.  */
                        pfound = p;
                        indfound = option_index;
                        exact = 1;
                        break;
                    } else if (pfound == NULL) {
                        /* First nonexact match found.  */
                        pfound = p;
                        indfound = option_index;
                    } else if (long_only || pfound->has_arg != p->has_arg || pfound->flag != p->flag
                            || pfound->val != p->val)
                        /* Second or later nonexact match found.  */
                        ambig = 1;
                }
            if (ambig && !exact) {
                if (print_errors) {
                    char *buf;

                    if (__asprintf(&buf, _("%s: option '-W %s' is ambiguous\n"), argv[0], d->optarg) >= 0) {
                        fprintf(stderr, "%s", buf);

                        free(buf);
                    }
                }
                d->nextchar += strlen(d->nextchar);
                d->optind++;
                return '?';
            }
            if (pfound != NULL) {
                option_index = indfound;
                if (*nameend) {
                    /* Don't test has_arg with >, because some C compilers don't
                     allow it to be used on enums.  */
                    if (pfound->has_arg)
                        d->optarg = nameend + 1;
                    else {
                        if (print_errors) {
                            char *buf;

                            if (__asprintf(&buf, _("\
%s: option '-W %s' doesn't allow an argument\n"), argv[0],
                                    pfound->name) >= 0) {
                                fprintf(stderr, "%s", buf);
                                free(buf);
                            }
                        }

                        d->nextchar += strlen(d->nextchar);
                        return '?';
                    }
                } else if (pfound->has_arg == 1) {
                    if (d->optind < argc)
                        d->optarg = argv[d->optind++];
                    else {
                        if (print_errors) {
                            char *buf;

                            if (__asprintf(&buf, _("\
%s: option '-W %s' requires an argument\n"), argv[0],
                                    pfound->name) >= 0) {
                                fprintf(stderr, "%s", buf);
                                free(buf);
                            }
                        }
                        d->nextchar += strlen(d->nextchar);
                        return optstring[0] == ':' ? ':' : '?';
                    }
                } else
                    d->optarg = NULL;
                d->nextchar += strlen(d->nextchar);
                if (longind != NULL)
                    *longind = option_index;
                if (pfound->flag) {
                    *(pfound->flag) = pfound->val;
                    return 0;
                }
                return pfound->val;
            }

            no_longs: d->nextchar = NULL;
            return 'W'; /* Let the application handle it.   */
        }
        if (temp[1] == ':') {
            if (temp[2] == ':') {
                /* This is an option that accepts an argument optionally.  */
                if (*d->nextchar != '\0') {
                    d->optarg = d->nextchar;
                    d->optind++;
                } else
                    d->optarg = NULL;
                d->nextchar = NULL;
            } else {
                /* This is an option that requires an argument.  */
                if (*d->nextchar != '\0') {
                    d->optarg = d->nextchar;
                    /* If we end this ARGV-element by taking the rest as an arg,
                     we must advance to the next element now.  */
                    d->optind++;
                } else if (d->optind == argc) {
                    if (print_errors) {
                        char *buf;

                        if (__asprintf(&buf, _("\
%s: option requires an argument -- '%c'\n"), argv[0], c) >= 0) {
                            fprintf(stderr, "%s", buf);
                            free(buf);
                        }
                    }
                    d->optopt = c;
                    if (optstring[0] == ':')
                        c = ':';
                    else
                        c = '?';
                } else
                    /* We already incremented `optind' once;
                     increment it again when taking next ARGV-elt as argument.  */
                    d->optarg = argv[d->optind++];
                d->nextchar = NULL;
            }
        }
        return c;
    }
}

int ecr_getopt(int argc, char * const *argv, const char *shortopts, ecr_getopt_data_t *data) {
    return ecr_getopt_internal_r(argc, argv, shortopts, NULL, NULL, 0, data, 0);
}

int ecr_getopt_long(int argc, char * const *argv, const char *shortopts, const ecr_option_t *longopts, int *longind,
        ecr_getopt_data_t *data) {
    return ecr_getopt_internal_r(argc, argv, shortopts, longopts, longind, 0, data, 0);
}

int ecr_getopt_long_only(int argc, char * const *argv, const char *shortopts, const ecr_option_t *longopts,
        int *longind, ecr_getopt_data_t *data) {
    return ecr_getopt_internal_r(argc, argv, shortopts, longopts, longind, 1, data, 0);
}

/*
 * c_log.h : MUL logging headers 
 *
 */

#ifndef _C_LOG_H
#define _C_LOG_H

#include <syslog.h>

/* Here is some guidance on logging levels to use:
 *
 * LOG_DEBUG	- For all messages that are enabled by optional debugging
 *		  features, typically preceded by "if (IS...DEBUG...)"
 * LOG_INFO	- Information that may be of interest, but everything seems
 *		  to be working properly.
 * LOG_NOTICE	- Only for message pertaining to daemon startup or shutdown.
 * LOG_WARNING	- Warning conditions: unexpected events, but the daemon believes
 *		  it can continue to operate correctly.
 * LOG_ERR	- Error situations indicating malfunctions.  Probably require
 *		  attention.
 *
 * Note: LOG_CRIT, LOG_ALERT, and LOG_EMERG are currently not used anywhere,
 * please use LOG_ERR instead.
 */

typedef enum 
{
  CLOG_NONE,
  CLOG_DEFAULT,
  CLOG_MUL,
  CLOG_EX
} clog_proto_t;

/* If maxlvl is set to CLOG_DISABLED, then no messages will be sent
   to that logging destination. */
#define CLOG_DISABLED	(LOG_EMERG-1)

typedef enum
{
  CLOG_DEST_SYSLOG = 0,
  CLOG_DEST_STDOUT,
  CLOG_DEST_MONITOR,
  CLOG_DEST_FILE
} clog_dest_t;
#define CLOG_NUM_DESTS		(CLOG_DEST_FILE+1)

struct clog 
{
  const char *ident;	/* daemon name (first arg to openlog) */
  clog_proto_t protocol;
  int maxlvl[CLOG_NUM_DESTS];	/* maximum priority to send to associated
  				   logging destination */
  int default_lvl;	/* maxlvl to use if none is specified */
  FILE *fp;
  char *filename;
  int facility;		/* as per syslog facility */
  int record_priority;	/* should messages logged through stdio include the
  			   priority of the message? */
  int syslog_options;	/* 2nd arg to openlog */
  int timestamp_precision;	/* # of digits of subsecond precision */
};

/* Message structure. */
struct cmessage
{
  int key;
  const char *str;
};

/* Default logging strucutre. */
extern struct clog *clog_default;

/* Open clog function */
extern struct clog *openclog (const char *progname, clog_proto_t protocol,
		              int syslog_options, int syslog_facility);

/* Close clog function. */
extern void closeclog (struct clog *zl);

/* GCC have printf type attribute check.  */
#ifdef __GNUC__
#define PRINTF_ATTRIBUTE(a,b) __attribute__ ((__format__ (__printf__, a, b)))
#else
#define PRINTF_ATTRIBUTE(a,b)
#endif /* __GNUC__ */

/* Generic function for clog. */
extern void c_log (struct clog *zl, int priority, const char *format, ...)
  PRINTF_ATTRIBUTE(3, 4);

/* Handy clog functions. */
extern void c_log_err (const char *format, ...) PRINTF_ATTRIBUTE(1, 2);
extern void c_log_warn (const char *format, ...) PRINTF_ATTRIBUTE(1, 2);
extern void c_log_info (const char *format, ...) PRINTF_ATTRIBUTE(1, 2);
extern void c_log_notice (const char *format, ...) PRINTF_ATTRIBUTE(1, 2);
extern void c_log_debug (const char *format, ...) PRINTF_ATTRIBUTE(1, 2);

/* For bgpd's peer oriented log. */
extern void clog_err (struct clog *, const char *format, ...)
  PRINTF_ATTRIBUTE(2, 3);
extern void clog_warn (struct clog *, const char *format, ...)
  PRINTF_ATTRIBUTE(2, 3);
extern void clog_info (struct clog *, const char *format, ...)
  PRINTF_ATTRIBUTE(2, 3);
extern void clog_notice (struct clog *, const char *format, ...)
  PRINTF_ATTRIBUTE(2, 3);
extern void clog_debug (struct clog *, const char *format, ...)
  PRINTF_ATTRIBUTE(2, 3);

/* Set logging level for the given destination.  If the log_level
   argument is CLOG_DISABLED, then the destination is disabled.
   This function should not be used for file logging (use clog_set_file
   or clog_reset_file instead). */
extern void clog_set_level (struct clog *zl, clog_dest_t, int log_level);
extern void clog_set_name (struct clog *zl, clog_proto_t protocol, char *name);

/* Set logging to the given filename at the specified level. */
extern int clog_set_file (struct clog *zl, const char *filename, int log_level);
/* Disable file logging. */
extern int clog_reset_file (struct clog *zl);

/* Rotate log. */
extern int clog_rotate (struct clog *);

/* For hackey massage lookup and check */
#define LOOKUP(x, y) mes_lookup(x, x ## _max, y, "(no item found)", #x)

extern const char *clookup (const struct cmessage *, int);
extern const char *mes_clookup (const struct cmessage *meslist, 
                               int max, int index,
                               const char *no_item, const char *mesname);

extern const char *clog_priority[];
extern char *clog_proto_names[];

/* Safe version of strerror -- never returns NULL. */
extern const char *safe_strerror(int errnum);

/* To be called when a fatal signal is caught. */
extern void clog_signal(int signo, const char *action
#ifdef SA_SIGINFO
			, siginfo_t *siginfo, void *program_counter
#endif
		       );

/* Log a backtrace. */
extern void clog_backtrace(int priority);

/* Log a backtrace, but in an async-signal-safe way.  Should not be
   called unless the program is about to exit or abort, since it messes
   up the state of clog file pointers.  If program_counter is non-NULL,
   that is logged in addition to the current backtrace. */
extern void clog_backtrace_sigsafe(int priority, void *program_counter);

/* Puts a current timestamp in buf and returns the number of characters
   written (not including the terminating NUL).  The purpose of
   this function is to avoid calls to localtime appearing all over the code.
   It caches the most recent localtime result and can therefore
   avoid multiple calls within the same second.  If buflen is too small,
   *buf will be set to '\0', and 0 will be returned. */
extern size_t log_timestamp(int timestamp_precision /* # subsecond digits */,
			       char *buf, size_t buflen);

/* structure useful for avoiding repeated rendering of the same timestamp */
struct ctimestamp_control {
   size_t len;		/* length of rendered timestamp */
   int precision;	/* configuration parameter */
   int already_rendered; /* should be initialized to 0 */
   char buf[40];	/* will contain the rendered timestamp */
};

/* Defines for use in command construction: */

#define LOG_LEVELS "(emergencies|alerts|critical|errors|warnings|notifications|informational|debugging)"

#define LOG_LEVEL_DESC \
  "System is unusable\n" \
  "Immediate action needed\n" \
  "Critical conditions\n" \
  "Error conditions\n" \
  "Warning conditions\n" \
  "Normal but significant conditions\n" \
  "Informational messages\n" \
  "Debugging messages\n"

#define LOG_FACILITIES "(kern|user|mail|daemon|auth|syslog|lpr|news|uucp|cron|local0|local1|local2|local3|local4|local5|local6|local7)"

#define LOG_FACILITY_DESC \
       "Kernel\n" \
       "User process\n" \
       "Mail system\n" \
       "System daemons\n" \
       "Authorization system\n" \
       "Syslog itself\n" \
       "Line printer system\n" \
       "USENET news\n" \
       "Unix-to-Unix copy system\n" \
       "Cron/at facility\n" \
       "Local use\n" \
       "Local use\n" \
       "Local use\n" \
       "Local use\n" \
       "Local use\n" \
       "Local use\n" \
       "Local use\n" \
       "Local use\n"

#define LOGFILE_MASK 0600

#endif /* _C_LOG_H */

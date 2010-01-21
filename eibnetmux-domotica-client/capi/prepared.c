/*
 * prepared.c - demonstrate how to use prepared statements.
 */

#include <my_global.h>
#include <my_sys.h>
#include <m_string.h>   /* for strdup() */
#include <mysql.h>
#include <my_getopt.h>


/*
 * eibtrace - eib packet trace
 *
 * eibnetmux - eibnet/ip multiplexer
 * Copyright (C) 2006-2008 Urs Zurbuchen <software@marmira.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

/*!
 * \example eibtrace.c
 *
 * Demonstrates usage of the EIBnetmux monitoring function.
 *
 * It produces a trace of requests seen on the KNX bus.
 */

/*!
 * \cond DeveloperDocs
 * \brief eibtrace - eib packet trace
 */

#ifdef HAVE_CONFIG_H
#include "../config.h"
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <libgen.h>
#include <getopt.h>
#include <errno.h>
#include <time.h>
#include <math.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include <eibnetmux/enmx_lib.h>
//#include "../mylib/mylib.h"
#include "mylib.h"
/*
 * EIB constants
 */
#define EIB_DAF_GROUP                   0x80
#define A_RESPONSE_VALUE_REQ            0x0040
#define A_WRITE_VALUE_REQ               0x0080


/*
 * Global variables
 */
ENMX_HANDLE     sock_con = 0;
unsigned char   conn_state = 0;

/*
 * local function declarations
 */
static void     Usage( char *progname );
static char     *knx_physical( uint16_t phy_addr );
static char     *knx_group( uint16_t grp_addr );


/*
 * EIB request frame
 */
typedef struct __attribute__((packed)) {
        uint8_t  code;
        uint8_t  zero;
        uint8_t  ctrl;
        uint8_t  ntwrk;
        uint16_t saddr;
        uint16_t daddr;
        uint8_t  length;
        uint8_t  tpci;
        uint8_t  apci;
        uint8_t  data[16];
} CEMIFRAME;


static void Usage( char *progname )
{
    fprintf( stderr, "Usage: %s [options] [hostname[:port]]\n"
                     "where:\n"
                     "  hostname[:port]                      defines eibnetmux server with default port of 4390\n"
                     "\n"
                     "options:\n"
                     "  -u user                              name of user                           default: -\n"
                     "  -c count                             stop after count number of requests    default: endless\n"
                     "  -q                                   no verbose output (default: no)\n"
                     "\n", basename( progname ));
}


int trace( int argc, char **argv )
{
    uint16_t                value_size;
    struct timeval          tv;
    struct tm               *ltime;
    uint16_t                buflen;
    unsigned char           *buf;
    CEMIFRAME               *cemiframe;
    int                     enmx_version;
    int                     c;
    int                     quiet = 0;
    int                     total = -1;
    int                     count = 0;
    int                     spaces = 1;
    char                    *user = NULL;
    char                    pwd[255];
    char                    *target;
    char                    *eis_types;
    int                     type;
    int                     seconds;
    unsigned char           value[20];
    uint32_t                *p_int = 0;
    double                  *p_real;

    opterr = 0;
    while( ( c = getopt( argc, argv, "c:u:q" )) != -1 ) {
        switch( c ) {
            case 'c':
                total = atoi( optarg );
                break;
            case 'u':
                user = strdup( optarg );
                break;
            case 'q':
                quiet = 1;
                break;
            default:
                fprintf( stderr, "Invalid option: %c\n", c );
                Usage( argv[0] );
                exit( -1 );
        }
    }
    if( optind == argc ) {
        target = NULL;
    } else if( optind + 1 == argc ) {
        target = argv[optind];
    } else {
        Usage( argv[0] );
        exit( -1 );
    }

    // catch signals for shutdown
    signal( SIGINT, Shutdown );
    signal( SIGTERM, Shutdown );

    // request monitoring connection
    enmx_version = enmx_init();
    sock_con = enmx_open( target, "eibtrace" );
    if( sock_con < 0 ) {
        fprintf( stderr, "Connect to eibnetmux failed (%d): %s\n", sock_con, enmx_errormessage( sock_con ));
        exit( -2 );
    }

    // authenticate
    if( user != NULL ) {
        if( getpassword( pwd ) != 0 ) {
            fprintf( stderr, "Error reading password - cannot continue\n" );
            exit( -6 );
        }
        if( enmx_auth( sock_con, user, pwd ) != 0 ) {
            fprintf( stderr, "Authentication failure\n" );
            exit( -3 );
        }
    }
    if( quiet == 0 ) {
        printf( "Connection to eibnetmux '%s' established\n", enmx_gethost( sock_con ));
    }

    buf = malloc( 10 );
    buflen = 10;
    if( total != -1 ) {
        spaces = floor( log10( total )) +1;
    }
    while( total == -1 || count < total ) {
        buf = enmx_monitor( sock_con, 0xffff, buf, &buflen, &value_size );
        if( buf == NULL ) {
            switch( enmx_geterror( sock_con )) {
                case ENMX_E_COMMUNICATION:
                case ENMX_E_NO_CONNECTION:
                case ENMX_E_WRONG_USAGE:
                case ENMX_E_NO_MEMORY:
                    fprintf( stderr, "Error on write: %s\n", enmx_errormessage( sock_con ));
                    enmx_close( sock_con );
                    exit( -4 );
                    break;
                case ENMX_E_INTERNAL:
                    fprintf( stderr, "Bad status returned\n" );
                    break;
                case ENMX_E_SERVER_ABORTED:
                    fprintf( stderr, "EOF reached: %s\n", enmx_errormessage( sock_con ));
                    enmx_close( sock_con );
                    exit( -4 );
                    break;
                case ENMX_E_TIMEOUT:
                    fprintf( stderr, "No value received\n" );
                    break;
            }
        } else {
            count++;
            cemiframe = (CEMIFRAME *) buf;
            gettimeofday( &tv, NULL );
            ltime = localtime( &tv.tv_sec );
            if( total != -1 ) {
                printf( "%*d: ", spaces, count );
            }
            printf( "%04d/%02d/%02d %02d:%02d:%02d:%03d - ",
                       ltime->tm_year + 1900, ltime->tm_mon +1, ltime->tm_mday,
                       ltime->tm_hour, ltime->tm_min, ltime->tm_sec, (uint32_t)tv.tv_usec / 1000 );
            printf( "%8s  ", knx_physical( cemiframe->saddr ));
            if( cemiframe->apci & A_WRITE_VALUE_REQ ) {
                printf( "W " );
            } else if( cemiframe->apci & A_RESPONSE_VALUE_REQ ) {
                printf( "A " );
            } else {
                printf( "R " );
            }
            printf( "%8s", (cemiframe->ntwrk & EIB_DAF_GROUP) ? knx_group( cemiframe->daddr ) : knx_physical( cemiframe->daddr ));
            if( cemiframe->apci & (A_WRITE_VALUE_REQ | A_RESPONSE_VALUE_REQ) ) {
                printf( " : " );
                p_int = (uint32_t *)value;
                p_real = (double *)value;
                switch( cemiframe->length ) {
                    case 1:     // EIS 1, 2, 7, 8
                        type = enmx_frame2value( 1, cemiframe, value );
                        printf( "%s | ", (*p_int == 0) ? "off" : "on" );
                        type = enmx_frame2value( 2, cemiframe, value );
                        printf( "%d | ", *p_int );
                        type = enmx_frame2value( 7, cemiframe, value );
                        printf( "%d | ", *p_int );
                        type = enmx_frame2value( 8, cemiframe, value );
                        printf( "%d", *p_int );
                        eis_types = "1, 2, 7, 8";
                        break;
                    case 2:     // 6, 13, 14
                        type = enmx_frame2value( 6, cemiframe, value );
                        printf( "%d%% | %d", *p_int * 100 / 255, *p_int );
                        type = enmx_frame2value( 13, cemiframe, value );
                        if( *p_int >=  0x20 && *p_int < 0x7f ) {
                            printf( " | %c", *p_int );
                            eis_types = "6, 14, 13";
                        } else {
                            eis_types = "6, 14";
                        }
                        break;
                    case 3:     // 5, 10
                        type = enmx_frame2value( 5, cemiframe, value );
                        printf( "%.2f | ", *p_real );
                        type = enmx_frame2value( 10, cemiframe, value );
                        printf( "%d", *p_int );
                        eis_types = "5, 10";
                        break;
                    case 4:     // 3, 4
                        type = enmx_frame2value( 3, cemiframe, value );
                        seconds = *p_int;
                        ltime->tm_hour = seconds / 3600;
                        seconds %= 3600;
                        ltime->tm_min = seconds / 60;
                        seconds %= 60;
                        ltime->tm_sec = seconds;
                        printf( "%02d:%02d:%02d | ", ltime->tm_hour, ltime->tm_min, ltime->tm_sec );
                        type = enmx_frame2value( 4, cemiframe, value );
                        ltime = localtime( (time_t *)p_int );
                        printf( "%04d/%02d/%02d", ltime->tm_year + 1900, ltime->tm_mon +1, ltime->tm_mday );
                        eis_types = "3, 4";
                        break;
                    case 5:     // 9, 11, 12
                        type = enmx_frame2value( 11, cemiframe, value );
                        printf( "%d | ", *p_int );
                        type = enmx_frame2value( 9, cemiframe, value );
                        printf( "%.2f", *p_real );
                        type = enmx_frame2value( 12, cemiframe, value );
                        // printf( "12: <->" );
                        eis_types = "9, 11, 12";
                        break;
                    default:    // 15
                        // printf( "%s", string );
                        eis_types = "15";
                        break;
                }
                if( cemiframe->length == 1 ) {
                    printf( " (%s", hexdump( &cemiframe->apci, 1, 1 ));
                } else {
                    printf( " (%s", hexdump( (unsigned char *)(&cemiframe->apci) +1, cemiframe->length -1, 1 ));
                }
                printf( " - eis types: %s)", eis_types );
            }
            printf( "\n" );
        }
    }
    return( 0 );
}


/*
 * Return representation of physical device KNX address as string
 */
static char *knx_physical( uint16_t phy_addr )
{
        static char     textual[64];
        int             area;
        int             line;
        int             device;

        phy_addr = ntohs( phy_addr );

        area = (phy_addr & 0xf000) >> 12;
        line = (phy_addr & 0x0f00) >> 8;
        device = phy_addr & 0x00ff;

        sprintf( textual, "%d.%d.%d", area, line, device );
        return( textual );
}


/*
 * Return representation of logical KNX group address as string
 */
static char *knx_group( uint16_t grp_addr )
{
        static char     textual[64];
        int             top;
        int             sub;
        int             group;

        grp_addr = ntohs( grp_addr );

        top = (grp_addr & 0x7800) >> 11;
        sub = (grp_addr & 0x0700) >> 8;
        group = grp_addr & 0x00ff;
        sprintf( textual, "%d/%d/%d", top, sub, group );
        return( textual );
}


/* @# _OPTION_ENUM_ */
#ifdef HAVE_OPENSSL
enum options_client
{
  OPT_SSL_SSL=256,
  OPT_SSL_KEY,
  OPT_SSL_CERT,
  OPT_SSL_CA,
  OPT_SSL_CAPATH,
  OPT_SSL_CIPHER,
  OPT_SSL_VERIFY_SERVER_CERT
};
#endif
/* @# _OPTION_ENUM_ */

static char *opt_host_name = NULL;    /* server host (default=localhost) */
static char *opt_user_name = NULL;    /* username (default=login name) */
static char *opt_password = NULL;     /* password (default=none) */
static unsigned int opt_port_num = 0; /* port number (use built-in value) */
static char *opt_socket_name = NULL;  /* socket name (use built-in value) */
static char *opt_db_name = NULL;      /* database name (default=none) */
static unsigned int opt_flags = 0;    /* connection flags (none) */

#include <sslopt-vars.h>

static int ask_password = 0;          /* whether to solicit password */

static MYSQL *conn;                   /* pointer to connection handler */

static const char *client_groups[] = { "client", NULL };

/* #@ _MY_OPTS_ */
static struct my_option my_opts[] =   /* option information structures */
{
  {"help", '?', "Display this help and exit",
  NULL, NULL, NULL,
  GET_NO_ARG, NO_ARG, 0, 0, 0, 0, 0, 0},
  {"host", 'h', "Host to connect to",
  (uchar **) &opt_host_name, NULL, NULL,
  GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"password", 'p', "Password",
  (uchar **) &opt_password, NULL, NULL,
  GET_STR, OPT_ARG, 0, 0, 0, 0, 0, 0},
  {"port", 'P', "Port number",
  (uchar **) &opt_port_num, NULL, NULL,
  GET_UINT, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"socket", 'S', "Socket path",
  (uchar **) &opt_socket_name, NULL, NULL,
  GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"user", 'u', "User name",
  (uchar **) &opt_user_name, NULL, NULL,
  GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},

#include <sslopt-longopts.h>

  { NULL, 0, NULL, NULL, NULL, NULL, GET_NO_ARG, NO_ARG, 0, 0, 0, 0, 0, 0 }
};
/* #@ _MY_OPTS_ */

static void
print_error (MYSQL *conn, char *message)
{
  fprintf (stderr, "%s\n", message);
  if (conn != NULL)
  {
    fprintf (stderr, "Error %u (%s): %s\n",
             mysql_errno (conn), mysql_sqlstate (conn), mysql_error (conn));
  }
}

/* #@ _PRINT_STMT_ERROR_ */
static void
print_stmt_error (MYSQL_STMT *stmt, char *message)
{
  fprintf (stderr, "%s\n", message);
  if (stmt != NULL)
  {
    fprintf (stderr, "Error %u (%s): %s\n",
             mysql_stmt_errno (stmt),
             mysql_stmt_sqlstate (stmt),
             mysql_stmt_error (stmt));
  }
}
/* #@ _PRINT_STMT_ERROR_ */

/* #@ _GET_ONE_OPTION_ */
static my_bool
get_one_option (int optid, const struct my_option *opt, char *argument)
{
  switch (optid)
  {
  case '?':
    my_print_help (my_opts);  /* print help message */
    exit (0);
  case 'p':                   /* password */
    if (!argument)            /* no value given; solicit it later */
      ask_password = 1;
    else                      /* copy password, overwrite original */
    {
      opt_password = strdup (argument);
      if (opt_password == NULL)
      {
        print_error (NULL, "could not allocate password buffer");
        exit (1);
      }
      while (*argument)
        *argument++ = 'x';
      ask_password = 0;
    }
    break;
#include <sslopt-case.h>
  }
  return (0);
}
/* #@ _GET_ONE_OPTION_ */

#include "process_prepared_statement.c"

struct EibtraceParameter
{
    char saddr[9];
    char w_r_a;
    double value;
    int length; //??
    int eis;
};

/*
void initEibtraceParameter(EibtraceParameter &init)
{
    init.saddr[0] = 0;
    init.w_r_a = 'n';
    init.value = 0.0;
    init.length = 0;
    init.eis = 0;
}

EibtraceParameter processEibtraceParameter(int argc, char * argv[])
{
    EibtraceParameter ret;
    initEibtraceParameter(ret);
    
    int i = 0;
    for( i = 0; i < argc; i++ )
    {
        //TODO: inserire controlli sugli "argv[i+1]" (i+1<argc, argv[i+1] in formato corretto)
        if( strcmp(argv[i],"-saddr") == 0 )
        {
            ret.saddr = argv[i]+1;
        }

        else if( strcmp(argv[i],"-apci") == 0 )
        {
            ret.w_r_a = argv[i]+1;
        }

        else if( strcmp(argv[i],"-value") == 0 )
        {
            ret.value = atof(argv[i+1]);
        }

        else if( strcmp(argv[i],"-length") == 0 )
        {
            ret.length = atoi(argv[i+1]);
        }

        else if( strcmp(argv[i],"-eis") == 0 )
        {
            ret.eis = atoi(argv[i+1]);
        }
        else
        {
            continue;
        }

        //TODO: Fare una funzione che automatizzi questo processo, e venga richiamata all'interno degli if.
        //dopo averlo usato, elimino il parametro slittando tutto e decrementanto i e argc
        int j = i;
        for( j = i; j < argc-1; j++ )
        {
            strcpy(argc[j], argc[j+1]);
        }
        argc--;
        i--;
        //NB: DOPO AVER FATTO LA FUNZIONE VA RICHIAMATA 2 VOLTE PER OGNI IF: 1 PER ARGOMENTO E 1 PARAMETRO ARGOMENTO
        //(es: -value 18.325     sono due stringhe)
        
    }

}*/

int main (int argc, char *argv[])
{

  
  trace(argc, argv);

  int opt_err;
  
  MY_INIT (argv[0]);
  load_defaults ("my", client_groups, &argc, &argv);

  if ((opt_err = handle_options (&argc, &argv, my_opts, get_one_option)))
    exit (opt_err);

  /* solicit password if necessary */
  if (ask_password)
    opt_password = get_tty_password (NULL);

  /* get database name if present on command line */
  if (argc > 0)
  {
    opt_db_name = argv[0];
    --argc; ++argv;
  }

  /* initialize client library */
  if (mysql_library_init (0, NULL, NULL))
  {
    print_error (NULL, "mysql_library_init() failed");
    exit (1);
  }

  /* initialize connection handler */
  conn = mysql_init (NULL);
  if (conn == NULL)
  {
    print_error (NULL, "mysql_init() failed (probably out of memory)");
    exit (1);
  }

#ifdef HAVE_OPENSSL
  /* pass SSL information to client library */
  if (opt_use_ssl)
    mysql_ssl_set (conn, opt_ssl_key, opt_ssl_cert, opt_ssl_ca,
                   opt_ssl_capath, opt_ssl_cipher);
#if (MYSQL_VERSION_ID >= 50023 && MYSQL_VERSION_ID < 50100) \
    || MYSQL_VERSION_ID >= 50111
  mysql_options (conn,MYSQL_OPT_SSL_VERIFY_SERVER_CERT,
                 (char*)&opt_ssl_verify_server_cert);
#endif
#endif

  /* connect to server */
  if (mysql_real_connect (conn, opt_host_name, opt_user_name, opt_password,
      opt_db_name, opt_port_num, opt_socket_name, opt_flags) == NULL)
  {
    print_error (conn, "mysql_real_connect() failed");
    mysql_close (conn);
    exit (1);
  }

  process_prepared_statements (conn);

  /* disconnect from server, terminate client library */
  mysql_close (conn);
  mysql_library_end ();
  exit (0);
}

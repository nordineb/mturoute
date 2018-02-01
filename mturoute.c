/*
mturoute!

by Eli Fulkerson, June 2005
see www.elifulkerson.com for updates.

Originally modified from Ping.c, by Francois Gouget (fgouget@free.fr), which was in turn
based on the ping sample provided with the ICMP libraries (author unknown), the FreeBSD
ping interface, and the FreeBSD traceroute interface.
His website: http://fgouget.free.fr/bing/index-en.shtml

Also incorporates bugfixes from Ivan Pepelnjak, October 2007.
His website: http://ioshints.blogspot.com/search?q=mturoute

*/

#include <stdio.h>
#include <time.h>
#include <winsock2.h>
#include <ipexport.h>
#include <icmpapi.h>
#include <ws2tcpip.h>
#include <conio.h>

//#include <limits.h>
#include <iphlpapi.h>

#define APP_NAME				"mturoute"
#define APP_VERSION				"3.0"

// predefined constants

#define ICMP_HEADER_SIZE        8		// Don't change this
#define IP_HEADER_SIZE			20		// Don't change this either

// option defaults

#define DEFAULT_OPT_I_VALUE     1		// Wait 1 second between ICMP packets
#define DEFAULT_OPT_M_VALUE     30		// Same as for TCP
#define DEFAULT_OPT_S_VALUE     56		// Add 56 bytes of data which makes for a 64 bytes ICMP packet.
#define DEFAULT_OPT_W_VALUE     3000L	// Wait for a reply for X milliseconds
#define OPT_P_MAX_SIZE          16		// Patterns are at most 16 bytes long
#define DEFAULT_OPT_R_VALUE		3		// Retry up to three times
#define DEFAULT_PAYLOAD_VALUE	10000	// somewhat low default in order to speed convergence time
#define DEFAULT_OPT_D_VALUE		0		// Debugging display off/on
#define DEFAULT_OPT_REDACT_VALUE	0		// auto-redaction of IP addresses is off

/**
 * A bit field for storing boolean options.
 * Note that in some cases the field is not a boolean and this variable 
 * simply stores whether the option has been used while the actual value is 
 * stored elswhere.
 */
unsigned short options=0;

//#define F_COUNT         0x0001
#define F_INTERVAL      0x0002
#define F_MAXTTL        0x0004
#define F_SLOW          0x0008
#define F_PATTERN       0x0010
#define F_QUIET         0x0020
#define F_IPV6		    0x0040
#define F_TRACE         0x0080
#define F_TIMEOUT       0x0100
#define F_RANDOMFILL    0x0200
#define F_FRAGMENT		0x0400
#define F_PAYLOAD		0x0800

int opt_i = DEFAULT_OPT_I_VALUE;
int opt_m = DEFAULT_OPT_M_VALUE;
int opt_s = DEFAULT_OPT_S_VALUE;
int opt_w = DEFAULT_OPT_W_VALUE;
int opt_r = DEFAULT_OPT_R_VALUE;
int opt_d = DEFAULT_OPT_D_VALUE;
int opt_p_length;	// pattern length
unsigned char opt_p_pattern[16];
int opt_payload = DEFAULT_PAYLOAD_VALUE;
int opt_redact = DEFAULT_OPT_REDACT_VALUE;
int opt_redact_count = 0;

int number_of_icmp_timeouts = 0; // number of times we've waited for an icmp timeout
int opt_timeout_explicit = 0;	// we have explicitly specified a timeout.  don't change what the user wants.

HANDLE hIcmp;
unsigned long count;
unsigned short icmp_data_size=0;
unsigned char* icmp_data=NULL;
unsigned char reply_buffer[10000];
struct icmp_echo_reply* icmp_reply;




// ivp6

//HANDLE hIcmp6;

/*
//from http://msdn.microsoft.com/en-us/library/ms738520(v=VS.85).aspx
int testlookup( char* host)
{

    //-----------------------------------------
    // Declare and initialize variables
    //WSADATA wsaData;
    //int iResult;
    INT iRetval;

    DWORD dwRetval;

    int i = 0;
	int done = 0;
	int choice = 0;
	char returnval[100];
	
    
    struct addrinfo *result = NULL;
    struct addrinfo *ptr = NULL;
    struct addrinfo hints;

    struct sockaddr_in  *sockaddr_ipv4;
//    struct sockaddr_in6 *sockaddr_ipv6;
    LPSOCKADDR sockaddr_ip;

    char ipstringbuffer[46];
    DWORD ipbufferlength = 46;


    //--------------------------------
    // Setup the hints address info structure
    // which is passed to the getaddrinfo() function
    ZeroMemory( &hints, sizeof(hints) );
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

	dwRetval = getaddrinfo(host, "", &hints, &result);
    if ( dwRetval != 0 ) {
        return 1;
    }

    //printf("getaddrinfo returned success\n");
    
    // Retrieve each address and print out the hex bytes
    for(ptr=result; ptr != NULL ;ptr=ptr->ai_next) {

        //printf("getaddrinfo response %d\n", i++);
        //printf("\tFlags: 0x%x\n", ptr->ai_flags);
        //printf("\tFamily: ");
		//printf("% d .. ",i);
        switch (ptr->ai_family) {
            case AF_UNSPEC:
                //printf("Unspecified\n");
                break;
            case AF_INET:
                //printf("AF_INET (IPv4)\n");
                sockaddr_ipv4 = (struct sockaddr_in *) ptr->ai_addr;
                //printf("%s (ipv4)\n", inet_ntoa(sockaddr_ipv4->sin_addr) );
				i++;
                break;
            case AF_INET6:
                sockaddr_ip = (LPSOCKADDR) ptr->ai_addr;
                // The buffer length is changed by each call to WSAAddresstoString
                // So we need to set it for each iteration through the loop for safety
                ipbufferlength = 46;
                iRetval = WSAAddressToString(sockaddr_ip, (DWORD) ptr->ai_addrlen, NULL, 
                    ipstringbuffer, &ipbufferlength );
                //if (iRetval)
                    //printf("WSAAddressToString failed with %u\n", WSAGetLastError() );
                //else    
                    //printf("%s (ipv6)\n", ipstringbuffer);
				i++;
                break;
            default:
                break;
        }
    }

	if ( i > 1 ) {
		printf("More than one IP address found.  Please select %d through %d:\n", 0, i - 1);
		i = 0;
	    for(ptr=result; ptr != NULL ;ptr=ptr->ai_next) {

			//printf("getaddrinfo response %d\n", i++);
			//printf("\tFlags: 0x%x\n", ptr->ai_flags);
			//printf("\tFamily: ");
			printf("% d .. ",i);
			switch (ptr->ai_family) {
				case AF_UNSPEC:
					printf("Unspecified\n");
					break;
				case AF_INET:
					//printf("AF_INET (IPv4)\n");
					sockaddr_ipv4 = (struct sockaddr_in *) ptr->ai_addr;
					printf("%s (ipv4)\n", inet_ntoa(sockaddr_ipv4->sin_addr) );
					i++;
					break;
				case AF_INET6:
					sockaddr_ip = (LPSOCKADDR) ptr->ai_addr;
					// The buffer length is changed by each call to WSAAddresstoString
					// So we need to set it for each iteration through the loop for safety
					ipbufferlength = 46;
					iRetval = WSAAddressToString(sockaddr_ip, (DWORD) ptr->ai_addrlen, NULL, ipstringbuffer, &ipbufferlength );
					if (iRetval)
						printf("WSAAddressToString failed with %u\n", WSAGetLastError() );
					else    
						printf("%s (ipv6)\n", ipstringbuffer);
					i++;
					break;
				default:
					break;
	        }
		}


		done = 0;
		while (done == 0) {
			choice = _getch();
			choice = choice - 48;  // ghetto convert to int

			if (choice >= i  || choice < 0) {
				printf("Please choose between %d and %d.\n", 0, i - 1);
			}
			else {
				done = 1;
			}
		}
	}

		i = 0;
	    for(ptr=result; ptr != NULL ;ptr=ptr->ai_next) {

			if (i == choice) {
				switch (ptr->ai_family) {
					case AF_UNSPEC:
						printf("Unspecified\n");
						break;
					case AF_INET:
						//printf("AF_INET (IPv4)\n");
						sockaddr_ipv4 = (struct sockaddr_in *) ptr->ai_addr;
						printf("%s (ipv4) chosen\n", inet_ntoa(sockaddr_ipv4->sin_addr) );
						printf("sprintfing");
						
						sprintf(returnval, "%s\0", inet_ntoa(sockaddr_ipv4->sin_addr));
						return returnval;
						//return sockaddr_ipv4;
						//printf("%s", returnval);
						//return ptr->ai_addr;
						//return result;

						i++;
						break;
					case AF_INET6:
						sockaddr_ip = (LPSOCKADDR) ptr->ai_addr;
						// The buffer length is changed by each call to WSAAddresstoString
						// So we need to set it for each iteration through the loop for safety
						ipbufferlength = 46;
						iRetval = WSAAddressToString(sockaddr_ip, (DWORD) ptr->ai_addrlen, NULL, ipstringbuffer, &ipbufferlength );
						if (!iRetval) {
							//printf("%s (ipv6) chosen\n", ipstringbuffer);
							//sprintf(returnval, "%s", ipstringbuffer);
							//return ipstringbuffer;
							//printf("%s", returnval);
							return ptr->ai_addr;
						}
						i++;
						break;
					default:
						break;
				}
			}
			i++;
		}


    freeaddrinfo(result);

    return 0;
}


*/


// On control-c, exit immediately.
BOOL WINAPI ConsoleCtrlHandler(DWORD dwCtrlType) {
    if (dwCtrlType == CTRL_C_EVENT) {
		exit(1);
	}
	return 0;
}

/*
 * Converts a string to an IP address. The address may be specified 
 * either as a host name or as the IP address in "dotted" format.
 *
 * @param host_string the host name / address
 * @return the host's IP address if successful, INADDR_NONE otherwise
 */

unsigned int HostString2Addr(char* host_string) {

    unsigned long int host_addr;

	//printf("host string %s host string\n", host_string);
    host_addr = inet_addr(host_string);
    if (host_addr == INADDR_NONE) {
        struct hostent* he;

        he = gethostbyname(host_string);
        if (he == NULL) {
            fprintf(stderr,"%s: unknown host %s\n", APP_NAME, host_string);
        }
		else if (he->h_addrtype != AF_INET) {
            fprintf(stderr,"%s: host %s is not in the AF_INET domain\n", APP_NAME, host_string);
        }
		else {
            memcpy(&host_addr, he->h_addr, sizeof(host_addr));
        }
    }
    return host_addr;
}

/*
 * Returns a pointer to a string suitable for representing the host's
 * address.
 */

char* HostAddr2String(unsigned long int host_addr, int options) {
    static char host_string[15+1+1+64+1+1];
    char* ip_str;


	// ip address redaction
	//  The value opt_redact_count increments with every hop in the topmost traceroute, which
	//  lets us assign a specific text value to each IP address without revealing them.. so people
	//  can paste output without leaking any secrets.  Will break if we ever use the
	//  hostaddr2string function out of sequence for any reason.

	char byte = opt_redact_count + 96;
	if (opt_redact == 1) {
		sprintf(host_string, "%c.%c.%c.%c", byte,byte,byte,byte);
		return host_string;
	}

    ip_str = inet_ntoa(*((struct in_addr*)&host_addr));
    //strncpy(host_string,ip_str,sizeof(host_string));
    strncpy_s(host_string, sizeof(host_string), ip_str, sizeof(host_string));

	host_string[sizeof(host_string)-1] = '\0';
    return host_string;
}

/*
 * Parses the pattern given by the user and places it in the pattern 
 * buffer in a form suitable for further use.
 * @return 0 if successful, -1 otherwise
 */
int GetPattern(char* pattern) {
    size_t i,l;
    char subpattern[3];
     
    l = strlen(pattern);
	
    if ((l > 32) || (l % 2 != 0)) {
        return -1;
	}
    i = 0;
    opt_p_length = 0;
    subpattern[2] = '\0';
    while (pattern[i] != '\0') {
        subpattern[0] = pattern[i++];
        subpattern[1] = pattern[i++];
        if (sscanf_s(subpattern, "%x", &l) != 1) {
            return -1;
		}
        opt_p_pattern[opt_p_length++] = (char)l;
    }
    return 0;
}

/*
 * Builds the data field to be sent with the ICMP packet.
 */
void GenerateData(int size) {
	int i;
	int r;

    if (icmp_data_size != size) {
        icmp_data_size = size;
        icmp_data=realloc(icmp_data, icmp_data_size);
    }
	
	if (options & F_PATTERN) {
		// Fill the buffer with the pattern
		i = 0;
		while (i < icmp_data_size) {
			memcpy(icmp_data + i, opt_p_pattern, min(opt_p_length, icmp_data_size - i));
			i += opt_p_length;
		}
		return;
	}

	if (options & F_RANDOMFILL) {
		// Initialise the ICMP payload with random data.
		// Because MAX_RAND is small only the low order byte is usable.
		for (i = 0; i < icmp_data_size; i++) {
			r = rand();
			icmp_data[i] = r & 0xff;
		}
			return;
	}

		
	// Default case: just put some predictible data in the packet.    
	for (i = 0; i < icmp_data_size; i++) {
		icmp_data[i] = (char)i;
	}
	return;
}


int doMTU(int target_addr, char *target_string, int MTU)	{
    int status;
    
	struct ip_option_information ip_opts;
	PICMP_ECHO_REPLY pEchoReply;
	int maxRetry;

    /* Prepare the IP options */
    memset(&ip_opts, 0, sizeof(ip_opts));
    ip_opts.Ttl = opt_m;
	maxRetry = opt_r;

	/* do not fragment */
	if (!(options & F_FRAGMENT)) {
		ip_opts.Flags = ip_opts.Flags + IP_FLAG_DF;
	}

	while (maxRetry > 0) {

        GenerateData(MTU);

		if (options & F_IPV6) {
			printf("IPV6 not yet supported.\n");
			exit(1);
		} else {

        status = IcmpSendEcho(hIcmp,
                              target_addr,
                              (LPVOID)icmp_data,
				   			  MTU,
                              &ip_opts,
                              reply_buffer,
                              sizeof(reply_buffer),
                              opt_w);
		}
		pEchoReply = (PICMP_ECHO_REPLY)reply_buffer;

		if (opt_d) {
			printf("doMTU: got return code %d for mtu %d\n", status, MTU);
		}

		//printf("original status %d", status);
		if (status == 0) {
			status = GetLastError();
			if (opt_d && (status > 1)) {
				printf("doMTU: GetLastError called after IcmpSendEcho returned %d\n",status); 
			}
		}
		else {
			if (opt_d && (status > 1)) {
				printf("doMTU: IcmpSendEcho returned error %d\n",status);
			}
		}

		if (status <= 1) {
			status=pEchoReply -> Status;
			if (opt_d && status) {
				printf("doMTU: IcmpSendEcho reply buffer contains %d\n",status);
			}
		}

		if (status == IP_PACKET_TOO_BIG) {
			return IP_PACKET_TOO_BIG;
		}

		if (status == IP_REQ_TIMED_OUT) {
			printf(".");
			maxRetry--;
			number_of_icmp_timeouts++;
			if (opt_d) {
				printf("doMTU: request timeout at mtu %d, %d tries left\n", MTU, maxRetry);
			}
			continue;
		}

		if (status == IP_DEST_NET_UNREACHABLE) {
			printf("u"); return 0;
		}

		if (opt_d) {
			printf("doMTU: returning status %d\n", status);
		}
		return status;
	}

	//return 1;
	if (opt_d) {
		printf("doMTU: Timed all the way out.\n");
	}

	if (opt_timeout_explicit == 0 && !(options & F_SLOW)) {
		if (opt_d) {
			printf("doMTU:  Assuming ICMP responses will not be coming.  Speeding things up.");
		}
		opt_w = 1000L;
		opt_r = 1;
	}

	return status;
}

void output_parameters()
{
	/* do not fragment */
	if (!(options & F_FRAGMENT)) {
		printf("* ICMP Fragmentation is not permitted. *\n");
	}
	else {
		printf("* ICMP Fragmentation is permitted. *\n");
	}

	if ((options & F_SLOW)) {
		printf("* Speed optimization is disabled *\n");
	}
	else {
		printf("* Speed optimization is enabled. *\n");
	}

	printf("* Maximum payload is %d bytes. *\n", opt_payload );
}

void formatResults(int success, int display, int current_check) {
		if (success == 0) {
			// mtu worked
			if (display == 1 || opt_d) {
				printf("+ ICMP payload of %d bytes succeeded.\n", current_check);
			}
			else {
				printf("+");
			}
			//min_mtu = current_check;
		}
		else {
			if (display == 1 || opt_d) {

				if (opt_d) {
					printf("icmp return code %d\n", success);
				}


				switch (success) {

					case IP_PACKET_TOO_BIG:// = 11009
						printf("- ICMP payload of %d bytes is too big.\n", current_check);
						break;

					case IP_BUF_TOO_SMALL://  = 11001
						printf("- ICMP payload of %d bytes failed. (IP_BUF_TOO_SMALL)\n", current_check, success);
						break;
					case IP_DEST_NET_UNREACHABLE:// = 11002
						printf("- ICMP payload of %d bytes failed. (IP_DEST_NET_UNREACHABLE)\n", current_check, success);
						break;
					case IP_DEST_HOST_UNREACHABLE://  = 11003
						printf("- ICMP payload of %d bytes failed. (IP_DEST_HOST_UNREACHABLE)\n", current_check, success);
						break;
					case IP_DEST_PROT_UNREACHABLE:// = 11004
						printf("- ICMP payload of %d bytes failed. (IP_DEST_PROT_UNREACHABLE)\n", current_check, success);
						break;
					case IP_DEST_PORT_UNREACHABLE://  = 11005
						printf("- ICMP payload of %d bytes failed. (IP_DEST_PORT_UNREACHABLE)\n", current_check, success);
						break;
					case IP_NO_RESOURCES:// = 11006
						printf("- ICMP payload of %d bytes failed. (IP_NO_RESOURCES)\n", current_check, success);
						break;
					case IP_BAD_OPTION:// = 11007
						printf("- ICMP payload of %d bytes failed. (IP_BAD_OPTION)\n", current_check, success);
						break;
					case IP_HW_ERROR://  = 11008
						printf("- ICMP payload of %d bytes failed. (IP_HW_ERROR)\n", current_check, success);
						break;
					case IP_REQ_TIMED_OUT:// = 11010
						printf("- ICMP payload of %d bytes failed. (IP_REQ_TIMED_OUT)\n", current_check, success);
						break;
					case IP_BAD_REQ://  = 11011
						printf("- ICMP payload of %d bytes failed. (IP_BAD_REQ)\n", current_check, success);
						break;
					case IP_BAD_ROUTE://  = 11012
						printf("- ICMP payload of %d bytes failed. (IP_BAD_ROUTE)\n", current_check, success);
						break;
					case IP_TTL_EXPIRED_TRANSIT:// = 11013
						printf("- ICMP payload of %d bytes failed. (IP_TTL_EXPIRED_TRANSIT)\n", current_check, success);
						break;
					case IP_TTL_EXPIRED_REASSEM://  = 11014
						printf("- ICMP payload of %d bytes failed. (IP_TTL_EXPIRED_REASSEM)\n", current_check, success);
						break;
					case IP_PARAM_PROBLEM://  = 11015
						printf("- ICMP payload of %d bytes failed. (IP_PARAM_PROBLEM)\n", current_check, success);
						break;
					case IP_SOURCE_QUENCH://  = 11016
						printf("- ICMP payload of %d bytes failed. (IP_SOURCE_QUENCH)\n", current_check, success);
						break;
					case IP_OPTION_TOO_BIG:// = 11017
						printf("- ICMP payload of %d bytes failed. (IP_OPTION_TOO_BIG)\n", current_check, success);
						break;
					case IP_BAD_DESTINATION://  = 11018
						printf("- ICMP payload of %d bytes failed. (IP_BAD_DESTINATION)\n", current_check, success);
						break;

					default:
						printf("? ICMP payload of %d bytes failed mysteriously.. (no ICMP response)\n", current_check);

				}
			} else {
				printf("-");
			}

			/*
			// mtu failed
			if (success == IP_PACKET_TOO_BIG) {
				if (display == 1) {
					printf("- ICMP payload of %d bytes is too big (IP_PACKET_TOO_BIG)\n", current_check);
				} else {
					printf("-");
				}


			} else {

				if (display == 1) {
					printf("? ICMP payload of %d bytes failed mysteriously..\n", current_check);
				}
				else {
					printf("?");
				}
			}
			//max_mtu = current_check;
			*/
		}
}

int doSingleMTU(int target_addr, char *target_string, int display, int last_cycle_result) {

	int min_mtu = 92;
	int max_mtu;
	int orig_max_mtu;
	int orig_min_mtu;

	int current_check;

	int success = 1;
	int precheck;

	int counter = 0;
	int last_checked = 0;

	int already_solved = -1;

    max_mtu = opt_payload;

	orig_min_mtu = min_mtu;
	orig_max_mtu = max_mtu;

	//while (counter < 10) {
	if (display == 1) {
		output_parameters();
	}

	if (!(options &  F_SLOW)) {
		

		/* Assume that a "correct" mtu, in most cases, is either 1500 or the result from the last attempt, and check that first */
		if (opt_d ) {
			printf("Optimizer: pre-checking %d bytes\n", last_cycle_result);
		}
		precheck = doMTU( target_addr, target_string, last_cycle_result);
		formatResults(precheck,display,last_cycle_result);

		if (precheck == 0) {
			if (opt_d) {
				printf("Optimizer: pre-checking %d bytes\n", last_cycle_result+1);
			}
			precheck = doMTU( target_addr, target_string, last_cycle_result+1);
			formatResults(precheck,display,last_cycle_result+1);

			if (precheck != 0) {
				// If we've already figured out that its 1500, we fake the normal display and skip the scan entirely.  No need to double our traffic.
				// we know the first attempt returned 0, since we're in this loop at all.  second attempt returned "precheck"

				//formatResults(0,display,last_cycle_result);
				//formatResults(precheck,display,last_cycle_result+1);
				already_solved = last_cycle_result;
			}
		} else {

			// we failed at "last_cycle_result", so its the working maximum
			max_mtu = last_cycle_result;
			last_checked = last_cycle_result;

			/* Lets speed failed links up a bit.  Pregame with a very small MTU request.  If it fails, then use then don't bother
			with the larger ones.  Otherwise, we get to wait for a lot of timeouts, since we won't converge until we hit the bottom*/
			if (opt_d) {
				printf("Optimizer: pre-checking %d bytes\n", min_mtu);
			}
			precheck = doMTU( target_addr, target_string, min_mtu);
			formatResults(precheck,display,min_mtu);
			if (precheck != 0) {
				// The minimum didn't even work, so lets skip the middle man
				max_mtu = min_mtu;
				last_checked = 0;  // should be low enough to bail us into the "not responding". 
			}
		}

	}

	while (min_mtu != max_mtu) {

		current_check = (max_mtu + min_mtu) / 2;

		// added last_checked -1 so that we don't have things like... 1472 Ok!  1473... bad  1472 Ok!
		// should never get a neighboring numbers anyway unless we are already converged, in theory
		if (last_checked - 1== min_mtu ) {
			last_checked = current_check;
			break;
		}

		if (last_checked == current_check) {
			break;
		}

		if (already_solved != -1) {
			last_checked = already_solved;
			break;
		}

		success = doMTU( target_addr, target_string, current_check );

		formatResults(success, display, current_check);

		if (success == 0) {
			// success
			min_mtu = current_check;
		}
		else {
			// failure
			max_mtu = current_check;
		}

		last_checked = current_check;
		Sleep(1000 * opt_i);
		counter++;

	}
	if (last_checked +1 >= orig_max_mtu && display == 1) {
		printf("Estimated Max: %d bytes or higher.\n", max_mtu);
	}
	else if (last_checked - 1 <= orig_min_mtu && display == 1) {
		printf("\nTarget is not responding to pings.\n");
	}
	else {
		if (display == 1) {
			/* do not fragment */
			if (!(options & F_FRAGMENT)) {
				printf ("Path MTU: %d bytes.\n", last_checked + ICMP_HEADER_SIZE + IP_HEADER_SIZE);
			}
			else {
				printf ("Max ping: %d bytes.\n", last_checked + ICMP_HEADER_SIZE + IP_HEADER_SIZE);
			}
		}
	}
	return last_checked + ICMP_HEADER_SIZE + IP_HEADER_SIZE;
}




/**
 * Sends ICMP echo Request packets with increasing TTLs to discover 
 * the list of hosts the packets are routed through on their way to  
 * the target host.
 *
 * @param target_addr internet address of the target host
 * @param target_string string to display for that host
 */
void doManyMTU(unsigned int target_addr, char* target_string) {
    int status;
    int hop,probe,nb_probes;
    unsigned int gateway_addr;
    struct ip_option_information ip_opts;
	int foundMTU;
	//int multiple_gateways;
	int last_cycle_result = 1472;  // used for speed optimizations

	if (opt_redact == 1) {
          printf("mturoute to [redacted], %d hops max, variable sized packets\n", opt_m, ICMP_HEADER_SIZE + opt_s);
	} else {
          printf("mturoute to %s, %d hops max, variable sized packets\n", target_string, opt_m, ICMP_HEADER_SIZE + opt_s);
	}
	output_parameters();


    /* Prepare the IP options */
    memset(&ip_opts, 0, sizeof(ip_opts));

	nb_probes = 3;
    for (hop=1;hop<opt_m;hop++) {

        printf("%2d  ",hop);
        ip_opts.Ttl = hop;
        gateway_addr = INADDR_NONE;

        /* Now we must send some probes with the specified TTL */
        for (probe = 0; probe < nb_probes; probe++) {
            GenerateData(opt_s);

			if (options & F_IPV6) {
				printf("do ipv6 here\n");
				exit(1);
			}
            status = IcmpSendEcho(hIcmp,
                                  target_addr,
                                  (LPVOID)icmp_data,
                                  icmp_data_size,
                                  &ip_opts,
                                  reply_buffer,
                                  sizeof(reply_buffer),
                                  opt_w);


            /* Report this probe's result */
            if (status == 0) {
                status = GetLastError();
				if (status != IP_REQ_TIMED_OUT) {
                    fprintf(stderr, "An error (%d) occurred while sending the ICMP Echo Request to %s\n", status, target_string);
				}
				else {
					if (probe == nb_probes -1) {
						if (probe > 0) {
							printf("No response from traceroute for this TTL.  Tried %d times\n", probe + 1);
						}
						else {
							printf("No response from traceroute for this TTL.  Tried %d time\n", probe + 1);
						}
					}
				}
			}
			else {
                if (gateway_addr == INADDR_NONE) {
                    gateway_addr = icmp_reply->Address;
					
					opt_redact_count++;  // so we can give different redacted strings (a.a.a.a, b.b.b.b etc)

					foundMTU = doSingleMTU(gateway_addr, target_string, 0, last_cycle_result);
					if (foundMTU != ICMP_HEADER_SIZE + IP_HEADER_SIZE) {
						printf("  host: %s  max: %d bytes \n", HostAddr2String(gateway_addr, options), foundMTU);
						last_cycle_result = foundMTU - (ICMP_HEADER_SIZE + IP_HEADER_SIZE);
					} 
					else {
						printf("  host: %s not responding\n", HostAddr2String(gateway_addr, options));
					}
                }
				else if (gateway_addr!=icmp_reply->Address)	{
						printf("*%d (An additional device responded for %s)\n", hop, HostAddr2String(gateway_addr, options));
                }
            }
        }
        
		if (gateway_addr == target_addr) {
            break;
		}
    }
}

/**
 * @param argc number of command-line options
 * @param argv command line options
 * @return 0 if sucessful, 2 for a usage error and 1 otherwise
 */
int main(int argc, char** argv) {
    int retcode;
    WSADATA wsaData;
    char** arg;

	if (argc < 2) {
        goto usage;
	}

    /* Initialisation */
    if (WSAStartup(MAKEWORD(1, 1), &wsaData)) {
        fprintf(stderr, "%s: You must use Winsock 1.1 or compatible\n", APP_NAME);
        goto error;
    }

    hIcmp = IcmpCreateFile();
	//hIcmp6 = Icmp6CreateFile();

    srand((int) time(NULL));
    /* Give a higher priority so that ping has better 
     * chances not to be delayed when measuring the RTT.
     */
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);

    icmp_reply = (struct icmp_echo_reply*)reply_buffer;

    /* Install the ^C handler */
    SetConsoleCtrlHandler(&ConsoleCtrlHandler, TRUE);

    /* Parse the parameters and do the pinging and traceing */
    retcode = 0;
    arg = argv + 1;
    GenerateData(opt_s);
    while (*arg != NULL) {
        if ((*arg)[0] == '-') {
            /* Change some option value */
            switch ((*arg)[1]) {

			case 'h':
			case '?':
				goto usage;
				break;

			case 'x':
				opt_redact = 1;
				break;

			case '6':
				/* turn on IPV6 mode */
				options |= F_IPV6;
				break;

            case 'd':
                 /* turns on debugging of ICMP status/failure codes */
				 opt_d++;
				 break;

            case 'i':
                /* Sets the interval between two echo requests. */
                arg++;
                if (sscanf_s(*arg, "%d", &opt_i) != 1)
                    goto usage;
                if (opt_i < 0)
                    opt_i = DEFAULT_OPT_I_VALUE;
                options |= F_INTERVAL;
                break;
            case 'r':
                /* Sets the retry count. */
                arg++;
                if (sscanf_s(*arg, "%d", &opt_r) != 1)
                    goto usage;
                if (opt_r < 0)
                    opt_r = DEFAULT_OPT_R_VALUE;
				opt_timeout_explicit = 1;
                break;

            case 'p':
                /* Pattern to use to fill the packets
                 */
                arg++;
                if (GetPattern(*arg) < 0) {
                    fprintf(stderr, "%s: incorrect pattern\n", APP_NAME);
                    goto usage;
                }
                options |= F_PATTERN;
                break;
            case 'q':
                /* Quiet option: only display a summary at the end.
                 * Only valid in ping mode.
                 */
                options |= F_QUIET;
                break;
            case 'm':
                /*
                 * Set the maximum payload size
                 */
                arg++;
                if (sscanf_s(*arg, "%d", &opt_payload) != 1)
                    goto usage;
				if (opt_payload <= 92 || opt_payload >= 65280) {
					fprintf(stderr, "Maximum payload must be between 92 and 65280 (inclusive).\n\n");
					goto end;
				}
                if (opt_payload < 0) {
                    opt_payload = DEFAULT_PAYLOAD_VALUE;
				}
                options |= F_PAYLOAD;
                break;
            case 't':
                /*
                 * Switch to traceroute mode.
                 */
                options |= F_TRACE;
                break;
            case 's':
                /*
                 * Skip speed optimizations.  Be slow.
                 */
                options |= F_SLOW;
                break;

			case 'f':
				/*
				 * Switch to nofragment mode.
				 */
				 options |= F_FRAGMENT;
				 break;
            case 'w':
                /*
                 * Sets the time to wait for a response to an Echo Request
                 */
                arg++;
                if (sscanf_s(*arg, "%d", &opt_w) != 1)
                    goto usage;
                if (opt_w < 0)
                    opt_w = DEFAULT_OPT_W_VALUE;
                options |= F_TIMEOUT;
				opt_timeout_explicit = 1;
                break;
            case 'z':
                /*
                 * Fills the ICMP packets with random data
                 */
                options = (options & ~F_PATTERN) | F_RANDOMFILL;
                break;
            case 'v':
                /*
                 * Output the version and quit
                 */
				fprintf(stdout, "v%s- compiled: %s %s", APP_VERSION, __DATE__, __TIME__);	


                return 0;
                break;
            }
        }
		else
		{
            unsigned long int host_addr;

            /* Get the target host address */
			//testlookup(*arg);
			//host_addr=testlookup(*arg);
			//printf("new %s new \n", host_addr);
            //host_addr=HostString2Addr(*arg);
			//printf("old %s old\n", host_addr);

			//host_addr=HostString2Addr(testlookup(*arg));
			host_addr=HostString2Addr(*arg);

            if (host_addr==INADDR_NONE) {
                retcode=1;
			}
            else { 
				if (options & F_TRACE) {
					doManyMTU(host_addr,*arg);
				}
				else {
					int tmp;
					tmp = doSingleMTU(host_addr,*arg, 1, 1472);
				}
			}
        }
        arg++;
    }

    /* Do some cleanup */
    IcmpCloseHandle( hIcmp );
    WSACleanup();
    free(icmp_data);

end:
    return retcode;

error:
    retcode = 1;
    goto end;

usage:
	fprintf(stderr, "*****************************************************************\n");
	fprintf(stderr, "  mturoute.exe - written by Eli Fulkerson, June 2005             \n");
	fprintf(stderr, "                 fixes by Ivan Pepelnjak, October 2007           \n");
	fprintf(stderr, "\n");
	fprintf(stderr, "  v%s - %s - %s\n", APP_VERSION, __DATE__, __TIME__);
	fprintf(stderr, "  http://www.elifulkerson.com/projects/mturoute.php for updates. \n");
	fprintf(stderr, "*****************************************************************\n");
	fprintf(stderr,  "\n");
    fprintf(stderr, "Usage: mturoute [-t] [-f] [-m MAX_PAYLOAD_SIZE] host \n");
    fprintf(stderr, "Flags:\n");
	fprintf(stderr, "   -t : Toggles 'traceroute' mode.  (Default is off)\n");
	fprintf(stderr, "   -f : Allow fragmentation.  This will return the max ping size that the\n");
	fprintf(stderr, "        target host will respond to, but not necessarily the MTU.\n");
	fprintf(stderr, "   -w : Set the number of milliseconds to wait for a response (default 3000).\n");
	fprintf(stderr, "   -r : Set the maximum number of probe retries on timeout (default = 3).\n");
	fprintf(stderr, "   -i : Set the interval between two echo requests.\n");
	fprintf(stderr, "   -d : Increases the debugging level. Reports ICMP status/failures.\n");
	fprintf(stderr, "   -m : Sets a maximum payload size to test. (Default is 10000)\n");
    fprintf(stderr, "   -v : Print version info and exit.\n");
	fprintf(stderr, "   -z : Fill ICMP packets with random data.\n");
	fprintf(stderr, "   -p : Fill ICMP packets with a specified pattern.\n");
	fprintf(stderr, "   -s : Skip speed optimizations.\n");
	fprintf(stderr, "   -x : Redact IP addresses in output.\n");
	fprintf(stderr, "-h,-? : Print usage information and exit.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Warning:  This utility generates a lot of ICMP traffic.\n");
    retcode = 2;
    goto end;

}

/*
Original credits for "ping.c"  (but version history removed, they aren't pertinent
   as ping.c is largely gutted.  Please blame any ugly code on the author of mturoute,
   not the original author!  -Eli) */

/**
 *			P I N G
 *
 * Using the Internet Control Message Protocol (ICMP) "ECHO" facility to:
 *  - provide network point-to-point statistics concerning packet loss
 *    and round time trip time
 *  - find the route packets take to reach a network host (and display
 *    network statistics about each host)
 *
 * Hack by Francois Gouget (fgouget@free.fr), based on:
 *  - the ping sample provided with the ICMP libraries (author unknown)
 *  - the FreeBSD ping interface
 *  - the FreeBSD traceroute interface
 *  - bing for these comments
 *
 * Comments and bug reports welcome !
 */
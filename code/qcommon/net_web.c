#include <emscripten.h>
#include <netdb.h>
#include <sys/socket.h>
#include "../client/client.h"
#include "../qcommon/q_shared.h"
#include "../qcommon/qcommon.h"
#include "../qcommon/q_queue.h"

static cvar_t *net_ip;
static cvar_t *net_port;

typedef struct {
  uint8_t* data;
  int length;
} packetdata_t;

static q_queue* packetQueue;

EMSCRIPTEN_KEEPALIVE
void NET_ReceivePacket(uint8_t *bytes, int length) {

  packetdata_t pkt;
  pkt.data = bytes;
  pkt.length = length;
  
  q_queue_push(packetQueue, &pkt);

}

void Sys_ShowIP(void) {}

void NET_Init(void) {
  net_ip = Cvar_Get("net_ip", "192.168.0.10", CVAR_LATCH);
  net_port = Cvar_Get("net_port", "27960", CVAR_LATCH);
  packetQueue = q_queue_create(sizeof(packetdata_t));

  Com_Printf("NET_Init %s:%s\n", net_ip->string, net_port->string);

  EM_ASM_(
      {
        var host = UTF8ToString($0);
        var port = UTF8ToString($1);
        var url = "http://" + host + ":" + port;
        console.log(url);
        var socket = new WuSocket(url);
        window.udpSocket = socket;

        socket.onopen = function() { console.log("webudp socket opened"); };
        socket.onmessage = function(evt) {
          if (Module._NET_ReceivePacket) {
            var nb = evt.data.byteLength;
            var ptr = Module._malloc(nb);
            var heapBytes = new Uint8Array(Module.HEAPU8.buffer, ptr, nb);
            heapBytes.set(new Uint8Array(evt.data));
            Module._NET_ReceivePacket(heapBytes.byteOffset, nb);
          }
        };
      },
      net_ip->string, net_port->string);
}

void NET_Shutdown(void) { Com_Printf("NET_Shutdown\n"); }

void NET_Sleep(int msec) {

	byte bufData[MAX_MSGLEN + 1];
  packetdata_t pkt;
  while (q_queue_pop(packetQueue, &pkt)) {

    if (pkt.length > sizeof(bufData)) {
      Com_Printf("packet too large: %d\n", pkt.length);
      free(pkt.data);
      continue;
    }

    netadr_t from = clc.serverAddress;
    //Com_Printf("[%s] RECV packet %d\n", NET_AdrToStringwPort(from), pkt.length);

    msg_t netmsg;
    MSG_Init(&netmsg, bufData, sizeof(bufData));
    memcpy(netmsg.data, pkt.data, pkt.length);
    netmsg.readcount = 0;
    netmsg.cursize = pkt.length;

    CL_PacketEvent(from, &netmsg);

    free(pkt.data);
  }
}

static void NetadrToSockadr(netadr_t *a, struct sockaddr *s) {
  if (a->type == NA_BROADCAST) {
    ((struct sockaddr_in *)s)->sin_family = AF_INET;
    ((struct sockaddr_in *)s)->sin_port = a->port;
    ((struct sockaddr_in *)s)->sin_addr.s_addr = INADDR_BROADCAST;
  } else if (a->type == NA_IP) {
    ((struct sockaddr_in *)s)->sin_family = AF_INET;
    ((struct sockaddr_in *)s)->sin_addr.s_addr = *(int *)&a->ip;
    ((struct sockaddr_in *)s)->sin_port = a->port;
  } else if (a->type == NA_IP6) {
    ((struct sockaddr_in6 *)s)->sin6_family = AF_INET6;
    ((struct sockaddr_in6 *)s)->sin6_addr = *((struct in6_addr *)&a->ip6);
    ((struct sockaddr_in6 *)s)->sin6_port = a->port;
    ((struct sockaddr_in6 *)s)->sin6_scope_id = a->scope_id;
  } else if (a->type == NA_MULTICAST6) {
    Com_Printf("NA_MULTICAST6\n");
  }
}

static void Sys_SockaddrToString(char *dest, int destlen,
                                 struct sockaddr *input) {
  socklen_t inputlen;

  if (input->sa_family == AF_INET6)
    inputlen = sizeof(struct sockaddr_in6);
  else
    inputlen = sizeof(struct sockaddr_in);

  if (getnameinfo(input, inputlen, dest, destlen, NULL, 0, NI_NUMERICHOST) &&
      destlen > 0)
    *dest = '\0';
}

const char *NET_AdrToString(netadr_t a) {
  static char s[NET_ADDRSTRMAXLEN];

  if (a.type == NA_LOOPBACK)
    Com_sprintf(s, sizeof(s), "loopback");
  else if (a.type == NA_BOT)
    Com_sprintf(s, sizeof(s), "bot");
  else if (a.type == NA_IP || a.type == NA_IP6) {
    struct sockaddr_storage sadr;

    memset(&sadr, 0, sizeof(sadr));
    NetadrToSockadr(&a, (struct sockaddr *)&sadr);
    Sys_SockaddrToString(s, sizeof(s), (struct sockaddr *)&sadr);
  }

  return s;
}

qboolean	NET_CompareAdr (netadr_t a, netadr_t b)
{
	if(!NET_CompareBaseAdr(a, b))
		return qfalse;
	
	if (a.type == NA_IP || a.type == NA_IP6)
	{
		if (a.port == b.port)
			return qtrue;
	}
	else
		return qtrue;
		
	return qfalse;
}

static struct addrinfo *SearchAddrInfo(struct addrinfo *hints,
                                       sa_family_t family) {
  while (hints) {
    if (hints->ai_family == family) return hints;

    hints = hints->ai_next;
  }

  return NULL;
}

static qboolean Sys_StringToSockaddr(const char *s, struct sockaddr *sadr,
                                     int sadr_len, sa_family_t family) {
  struct addrinfo hints;
  struct addrinfo *res = NULL;
  struct addrinfo *search = NULL;
  struct addrinfo *hintsp;
  int retval;

  memset(sadr, '\0', sizeof(*sadr));
  memset(&hints, '\0', sizeof(hints));

  hintsp = &hints;
  hintsp->ai_family = family;
  hintsp->ai_socktype = SOCK_DGRAM;

  retval = getaddrinfo(s, NULL, hintsp, &res);

  if (!retval) {
    if (family == AF_UNSPEC) {
      search = SearchAddrInfo(res, AF_INET);
    } else
      search = SearchAddrInfo(res, family);

    if (search) {
      if (search->ai_addrlen > sadr_len) search->ai_addrlen = sadr_len;

      memcpy(sadr, search->ai_addr, search->ai_addrlen);
      freeaddrinfo(res);

      return qtrue;
    } else
      Com_Printf(
          "Sys_StringToSockaddr: Error resolving %s: No address of required "
          "type found.\n",
          s);
  } else
    Com_Printf("Sys_StringToSockaddr: Error resolving %s: %s\n", s,
               gai_strerror(retval));

  if (res) freeaddrinfo(res);

  return qfalse;
}

static void SockadrToNetadr(struct sockaddr *s, netadr_t *a) {
  if (s->sa_family == AF_INET) {
    a->type = NA_IP;
    *(int *)&a->ip = ((struct sockaddr_in *)s)->sin_addr.s_addr;
    a->port = ((struct sockaddr_in *)s)->sin_port;
  }
}

qboolean Sys_StringToAdr(const char *s, netadr_t *a, netadrtype_t family) {
  Com_Printf("Sys_StringToAdr %s\n", s);
  struct sockaddr_storage sadr;
  sa_family_t fam;

  switch (family) {
    case NA_IP:
      fam = AF_INET;
      break;
    case NA_IP6:
      fam = AF_INET6;
      break;
    default:
      fam = AF_UNSPEC;
      break;
  }
  if (!Sys_StringToSockaddr(s, (struct sockaddr *)&sadr, sizeof(sadr), fam)) {
    return qfalse;
  }

  SockadrToNetadr((struct sockaddr *)&sadr, a);
  return qtrue;
}

qboolean Sys_IsLANAddress( netadr_t adr ) {
	int		index, run, addrsize;
	qboolean differed;
	byte *compareadr, *comparemask, *compareip;

	if( adr.type == NA_LOOPBACK ) {
		return qtrue;
	}

	if( adr.type == NA_IP )
	{
		// RFC1918:
		// 10.0.0.0        -   10.255.255.255  (10/8 prefix)
		// 172.16.0.0      -   172.31.255.255  (172.16/12 prefix)
		// 192.168.0.0     -   192.168.255.255 (192.168/16 prefix)
		if(adr.ip[0] == 10)
			return qtrue;
		if(adr.ip[0] == 172 && (adr.ip[1]&0xf0) == 16)
			return qtrue;
		if(adr.ip[0] == 192 && adr.ip[1] == 168)
			return qtrue;

		if(adr.ip[0] == 127)
			return qtrue;
	}
	
	return qfalse;
}

void Sys_SendPacket(int length, const void *data, netadr_t to) {
  if (to.type == NA_IP) {
    EM_ASM_(
        {
          var content = new Uint8Array(Module.HEAPU8.buffer, $0, $1);
          window.udpSocket.send(content);
        },
        data, length);
  } else {
    Com_Printf("skip packet packet type %d\n", to.type);
  }
}

qboolean NET_CompareBaseAdrMask(netadr_t a, netadr_t b, int netmask)
{
	byte cmpmask, *addra, *addrb;
	int curbyte;
	
	if (a.type != b.type)
		return qfalse;

	if (a.type == NA_LOOPBACK)
		return qtrue;

	if(a.type == NA_IP)
	{
		addra = (byte *) &a.ip;
		addrb = (byte *) &b.ip;
		
		if(netmask < 0 || netmask > 32)
			netmask = 32;
	}
	else if(a.type == NA_IP6)
	{
		addra = (byte *) &a.ip6;
		addrb = (byte *) &b.ip6;
		
		if(netmask < 0 || netmask > 128)
			netmask = 128;
	}
	else
	{
		Com_Printf ("NET_CompareBaseAdr: bad address type\n");
		return qfalse;
	}

	curbyte = netmask >> 3;

	if(curbyte && memcmp(addra, addrb, curbyte))
			return qfalse;

	netmask &= 0x07;
	if(netmask)
	{
		cmpmask = (1 << netmask) - 1;
		cmpmask <<= 8 - netmask;

		if((addra[curbyte] & cmpmask) == (addrb[curbyte] & cmpmask))
			return qtrue;
	}
	else
		return qtrue;
	
	return qfalse;
}


qboolean NET_CompareBaseAdr (netadr_t a, netadr_t b)
{
	return NET_CompareBaseAdrMask(a, b, -1);
}

qboolean NET_IsLocalAddress(netadr_t adr) {
  return qtrue;
}

void NET_Restart_f(void) {
  Com_Printf("NET_Restart_f\n");
  // NET_Config(qtrue);
}

const char *NET_AdrToStringwPort(netadr_t a) {
  static char s[NET_ADDRSTRMAXLEN];

  if (a.type == NA_LOOPBACK)
    Com_sprintf(s, sizeof(s), "loopback");
  else if (a.type == NA_BOT)
    Com_sprintf(s, sizeof(s), "bot");
  else if (a.type == NA_IP)
    Com_sprintf(s, sizeof(s), "%s:%hu", NET_AdrToString(a), ntohs(a.port));
  else if (a.type == NA_IP6)
    Com_sprintf(s, sizeof(s), "[%s]:%hu", NET_AdrToString(a), ntohs(a.port));

  return s;
}

void NET_JoinMulticast6(void) { Com_Printf("NET_JoinMulticast6\n"); }

void NET_LeaveMulticast6() { Com_Printf("leave multicast6\n"); }

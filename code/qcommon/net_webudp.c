#include <Wu.h>
#include <WuHost.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "../qcommon/q_shared.h"
#include "../qcommon/qcommon.h"

static cvar_t *net_ip;
static cvar_t *net_port;
static cvar_t *max_clients;
WuHost *webudp = NULL;

void Sys_ShowIP(void) {}

void NET_Init(void) {
  net_ip = Cvar_Get("net_ip", "192.168.0.10", CVAR_LATCH);
  net_port = Cvar_Get("net_port", "27960", CVAR_LATCH);
  max_clients = Cvar_Get("sv_maxclients", va("%i", 16), CVAR_LATCH);

  Com_Printf("NET_Init %s:%s [max clients %d]\n", net_ip->string,
             net_port->string, max_clients->integer);
  int32_t status = WuHostCreate(net_ip->string, net_port->string,
                                256, &webudp);

  if (status != WU_OK) {
    Com_Printf("WebUDP creation failed\n");
    return;
  }
}

void NET_Shutdown(void) { Com_Printf("NET_Shutdown\n"); }

void NET_Sleep(int msec) {
  if (!webudp) {
    Com_Printf("no webudp\n");
    return;
  }

	byte bufData[MAX_MSGLEN + 1];
  WuEvent evt;
  while (WuHostServe(webudp, &evt, msec)) {
    switch (evt.type) {
      case WuEvent_BinaryData: {
        if (evt.length > sizeof(bufData)) {
          Com_Printf("packet too large: %d\n", evt.length);
          continue;
        }

        WuAddress addr = WuClientGetAddress(evt.client);

        netadr_t from;
        from.type = NA_IP;
        memcpy(from.ip, &addr.host, 4);
        from.port = BigShort(addr.port);

        msg_t netmsg;
		    MSG_Init(&netmsg, bufData, sizeof(bufData));

        memcpy(netmsg.data, evt.data, evt.length);
				netmsg.readcount = 0;
        netmsg.cursize = evt.length;

        if (com_sv_running->integer) {
          Com_RunAndTimeServerPacket(&from, &netmsg); 
        }

        break;
      }
      case WuEvent_ClientJoin: {
        WuAddress addr = WuClientGetAddress(evt.client);
        Com_Printf("client join (%u:%u)\n", addr.host, addr.port);
        break;
      }
      case WuEvent_ClientLeave: {
        Com_Printf("client leave %p\n", evt.client);
        WuHostRemoveClient(webudp, evt.client);
        break;
      }
      case WuEvent_TextData: {
        Com_Printf("text data\n");
        break;
      }
      default: break;
    }
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

qboolean NET_CompareAdr(netadr_t a, netadr_t b) { return qfalse; }

qboolean Sys_StringToAdr(const char *s, netadr_t *a, netadrtype_t family) {
  Com_Printf("Sys_StringToAdr %s\n", s);
  return qfalse;
}

qboolean Sys_IsLANAddress( netadr_t adr ) {
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

WuAddress NET_AdrToWuAddress(netadr_t a) {
  WuAddress b;
  b.host = *(int*)a.ip;
  b.port = ntohs(a.port);
  return b;
}

void Sys_SendPacket(int length, const void *data, netadr_t to) {

  Com_Printf("Sys_SendPacket to [%s] size: %d\n", NET_AdrToStringwPort(to), length);
  WuAddress addr = NET_AdrToWuAddress(to);

  WuClient* client = WuHostFindClient(webudp, addr);

  if (client) {
    WuHostSendBinary(webudp, client, data, length);
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

qboolean NET_IsLocalAddress(netadr_t adr) { return qtrue; }

void NET_Restart_f(void) {
  Com_Printf("NET_Restart_f\n");
  // NET_Config(qtrue);
}

void NET_JoinMulticast6(void) { Com_Printf("NET_JoinMulticast6\n"); }

void NET_LeaveMulticast6() { Com_Printf("leave multicast6\n"); }

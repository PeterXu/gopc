// Based-on https://github.com/xhs/gosctp
package gopc

/*
#cgo pkg-config: usrsctp
#cgo CFLAGS: -Wno-deprecated -std=c99

#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <usrsctp.h>


// The highest stream ID (Sid) that SCTP allows, and the number of streams we
// tell SCTP we're going to use.
#define kMaxSctpSid     1023

// This is the default SCTP port to use. It is passed along the wire and the
// connectee and connector must be using the same port. It is not related to the
// ports at the IP level. (Corresponds to: sockaddr_conn.sconn_port in usrsctp.h)
#define kSctpDefaultPort 5000

// For the list of IANA approved values see:
// http://www.iana.org/assignments/sctp-parameters/sctp-parameters.xml
// The value is not used by SCTP itself. It indicates the protocol running
// on top of SCTP.
enum PayloadProtocolIdentifier {
  PPID_NONE           = 0, // No protocol is specified.
  PPID_CONTROL        = 50,
  PPID_BINARY_PARTIAL = 52,
  PPID_BINARY_LAST    = 53,
  PPID_TEXT_PARTIAL   = 54,
  PPID_TEXT_LAST      = 51,
};

// DataMessageType is used for the SCTP "Payload Protocol Identifier", as
// defined in http://tools.ietf.org/html/rfc4960#section-14.4
typedef enum DataMessageType {
  DMT_NONE                    = 0,
  DMT_CONTROL                 = 1,
  DMT_BINARY                  = 2,
  DMT_TEXT                    = 3,
}DataMessageType;

static int get_sctp_ppid(DataMessageType type) {
  switch(type) {
  case DMT_NONE:
    return PPID_NONE;
  case DMT_CONTROL:
    return PPID_CONTROL;
  case DMT_BINARY:
    return PPID_BINARY_LAST;
  case DMT_TEXT:
    return PPID_TEXT_LAST;
  }
  return PPID_NONE;
}

typedef struct {
  uint32_t ssrc;
  DataMessageType type;
  bool ordered;
  bool reliable;
  int max_rtx_count;
  int max_rtx_ms;
}send_param;

static send_param *new_send_param(uint32_t sid, int type, bool ordered) {
  send_param *param = malloc(sizeof(send_param));
  memset(param, 0, sizeof(send_param));
  param->ssrc = sid;
  param->type = type;
  param->ordered = ordered;
  return param;
}


// A Engine that interacts with usrsctp.

typedef struct {
  struct socket *sock;
  void *udata;
} sctp_transport;

static sctp_transport *new_sctp_transport(void *udata) {
  sctp_transport *sctp = (sctp_transport *)malloc(sizeof(sctp_transport));
  if (sctp != NULL) {
    sctp->sock = NULL;
    sctp->udata = udata;
  }
  return sctp;
}


extern void go_sctp_data_ready_cb(sctp_transport *sctp, void *data, size_t len);

static int sctp_data_ready_cb(void *addr, void *data, size_t len, uint8_t tos, uint8_t set_df) {
  go_sctp_data_ready_cb((sctp_transport *)addr, data, len);
  return 0;
}

extern void go_sctp_data_received_cb(sctp_transport *sctp, void *data, size_t len, int sid, int ppid);
extern void go_sctp_notification_received_cb(sctp_transport *sctp, void *data, size_t len);

static int sctp_data_received_cb(struct socket *sock, union sctp_sockstore addr, void *data,
                                 size_t len, struct sctp_rcvinfo recv_info, int flags, void *udata) {
  sctp_transport *sctp = (sctp_transport *)udata;
  if (flags & MSG_NOTIFICATION)
    go_sctp_notification_received_cb(sctp, data, len);
  else
    go_sctp_data_received_cb(sctp, data, len, recv_info.rcv_sid, ntohl(recv_info.rcv_ppid));
  free(data);
  return 0;
}

extern void go_debug_sctp_printf(char *cstr);

static void debug_sctp_printf(const char *format, ...) {
  char s[1024] = {0};
  va_list ap;
  va_start(ap, format);
  vsnprintf(s, sizeof(s)-1, format, ap);
  //printf("SCTP: %s\n", s);
  go_debug_sctp_printf(s);
  va_end(ap);
}


static void init_sctp() {
  usrsctp_init(0, sctp_data_ready_cb, debug_sctp_printf);

  // To turn on/off detailed SCTP debugging.
  //usrsctp_sysctl_set_sctp_debug_on(SCTP_DEBUG_ALL);

  usrsctp_sysctl_set_sctp_ecn_enable(0);

  // Add a blackhole sysctl. Setting it to 1 results in no ABORTs
  // being sent in response to INITs, setting it to 2 results
  // in no ABORTs being sent for received OOTB packets.
  // This is similar to the TCP sysctl.
  // usrsctp_sysctl_set_sctp_blackhole(2);

  // Set the number of default outgoing streams.
  usrsctp_sysctl_set_sctp_nr_outgoing_streams_default(kMaxSctpSid);
}

static bool open_sctp_socket(sctp_transport *sctp) {
  if (!sctp || sctp->sock)
    return false;

  struct socket *s = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP,
                                    sctp_data_received_cb, NULL, 0, sctp);
  if (s == NULL)
    return false;

  // Make the socket non-blocking
  if (usrsctp_set_non_blocking(s, 1) < 0)
    return false;

  // This ensures that the usrsctp close call deletes the association. This
  // prevents usrsctp from calling OnSctpOutboundPacket with references to
  // this class as the address.
  struct linger lopt;
  lopt.l_onoff = 1;
  lopt.l_linger = 0;
  if (usrsctp_setsockopt(s, SOL_SOCKET, SO_LINGER, &lopt, sizeof(lopt)))
    return false;

  // Enable stream ID resets.
  struct sctp_assoc_value rst;
  rst.assoc_id = SCTP_ALL_ASSOC;
  rst.assoc_value = 1;
  if (usrsctp_setsockopt(s, IPPROTO_SCTP, SCTP_ENABLE_STREAM_RESET, &rst, sizeof(rst)))
    return false;

  // Nagle.
  uint32_t nodelay = 1;
  if (usrsctp_setsockopt(s, IPPROTO_SCTP, SCTP_NODELAY, &nodelay, sizeof(nodelay)))
    return false;

  // TODO:Subscribe to SCTP event notifications.
  int event_types[] = {
    SCTP_ASSOC_CHANGE,
    SCTP_PEER_ADDR_CHANGE,
    SCTP_SEND_FAILED_EVENT,
    SCTP_SENDER_DRY_EVENT,
    SCTP_STREAM_RESET_EVENT
  };
  struct sctp_event event = {0};
  event.se_assoc_id = SCTP_ALL_ASSOC;
  event.se_on = 1;
  for (int i=0; i < sizeof(event_types)/sizeof(int); i++) {
    event.se_type = event_types[i];
    if (usrsctp_setsockopt(s, IPPROTO_SCTP, SCTP_EVENT, &event, sizeof(event)) < 0)
      return false;
  }

#if 0
  struct sctp_paddrparams addr_param;
  memset(&addr_param, 0, sizeof addr_param);
  addr_param.spp_flags = SPP_PMTUD_DISABLE;
  addr_param.spp_pathmtu = 1200;
  if (usrsctp_setsockopt(s, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS, &addr_param, sizeof(addr_param)))
    return false;

  struct sctp_initmsg init_msg;
  memset(&init_msg, 0, sizeof init_msg);
  init_msg.sinit_num_ostreams = 1024;
  init_msg.sinit_max_instreams = 1023;
  if (usrsctp_setsockopt(s, IPPROTO_SCTP, SCTP_INITMSG, &init_msg, sizeof init_msg))
    return false;
#endif

  sctp->sock = s;
  usrsctp_register_address(sctp);

  return true;
}

static void release_usrsctp() {
#if 0
  // usrsctp_finish() may fail if it's called too soon after the channels are
  // closed. Wait and try again until it succeeds for up to 3 seconds.
  for (size_t i = 0; i < 300; ++i) {
    if(usrsctp_finish() == 0) break;
    usleep(10);
  }
#endif
}

static int send_sctp(sctp_transport *sctp,
                     void *data, size_t len, send_param *param)
{
  struct sctp_sendv_spa spa = {0};
  spa.sendv_flags |= SCTP_SEND_SNDINFO_VALID;
  spa.sendv_sndinfo.snd_sid = param->ssrc;
  spa.sendv_sndinfo.snd_ppid = htonl(get_sctp_ppid(param->type));
  spa.sendv_sndinfo.snd_flags |= SCTP_EOR;

  // Ordered implies reliable.
  if (!param->ordered) {
    spa.sendv_sndinfo.snd_flags |= SCTP_UNORDERED;
    if (param->max_rtx_count >= 0 || param->max_rtx_ms == 0) {
      spa.sendv_flags |= SCTP_SEND_PRINFO_VALID;
      spa.sendv_prinfo.pr_policy = SCTP_PR_SCTP_RTX;
      spa.sendv_prinfo.pr_value = param->max_rtx_count;
    }else {
      spa.sendv_flags |= SCTP_SEND_PRINFO_VALID;
      spa.sendv_prinfo.pr_policy = SCTP_PR_SCTP_TTL;
      spa.sendv_prinfo.pr_value = param->max_rtx_ms;
    }
  }

  // We don't fragment.
  ssize_t send_res = usrsctp_sendv(sctp->sock, data, len, NULL, 0,
                                   &spa, sizeof(spa), SCTP_SENDV_SPA, 0);
  if (send_res < 0) {
    return errno;
  }
  return 0;
}

static int send_sctp2(sctp_transport *sctp,
                      void *data, size_t len, uint16_t sid, uint32_t ppid)
{
  struct sctp_sndinfo info;
  memset(&info, 0, sizeof info);
  info.snd_sid = sid;
  info.snd_flags = SCTP_EOR;
  info.snd_ppid = htonl(ppid);

  ssize_t send_res = usrsctp_sendv(sctp->sock, data, len, NULL, 0,
                                   &info, sizeof info, SCTP_SENDV_SNDINFO, 0);
  if (send_res < 0) {
    return errno;
  }
  return 0;
}


static struct sockaddr_conn sctp_sockaddr(int port, void *udata) {
  struct sockaddr_conn sconn = {0};
  sconn.sconn_family = AF_CONN;
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
  sconn.sconn_len = sizeof(sconn);
#endif
  // Note: conversion from int to uint16_t happens here.
  sconn.sconn_port = htons(port);
  sconn.sconn_addr = udata;
  return sconn;
}

static int connect_sctp(sctp_transport *sctp, int local_port, int remote_port) {
  struct sockaddr_conn local_sconn = sctp_sockaddr(local_port, (void *)sctp);
  if (usrsctp_bind(sctp->sock, (struct sockaddr *)&local_sconn, sizeof(local_sconn)) < 0)
    return errno;

  struct sockaddr_conn remote_sconn = sctp_sockaddr(remote_port, (void *)sctp);
  int ret = usrsctp_connect(sctp->sock, (struct sockaddr *)&remote_sconn, sizeof(remote_sconn));
  if (ret < 0 && errno != EINPROGRESS) {
    return errno;
  }
  return 0;
}

static int accept_sctp(sctp_transport *sctp, int port) {
  struct sockaddr_conn sconn = sctp_sockaddr(port, (void *)sctp);
  usrsctp_listen(sctp->sock, 1);
  socklen_t len = sizeof sconn;
  struct socket *s = usrsctp_accept(sctp->sock, (struct sockaddr *)&sconn, &len);
  if (s) {
    struct socket *t = sctp->sock;
    sctp->sock = s;
    usrsctp_close(t);
    return 0;
  }

  return errno;
}

*/
import "C"

import (
	"errors"
	"log"
	"sync"
	"unsafe"
)

func init() {
	C.init_sctp()
}

type SctpData struct {
	Sid  int
	Ppid int
	Data []byte
}

type SctpTransport struct {
	sctp          *C.sctp_transport
	ready         bool
	localPort     int
	remotePort    int
	BufferChannel chan []byte
	DataChannel   chan *SctpData
	sync.Mutex
}

func NewSctpTransport() (*SctpTransport, error) {
	sctp := C.new_sctp_transport(nil)
	if sctp == nil {
		return nil, errors.New("fail to create SCTP transport")
	}
	s := &SctpTransport{
		sctp:          sctp,
		ready:         true,
		localPort:     C.kSctpDefaultPort,
		remotePort:    C.kSctpDefaultPort,
		BufferChannel: make(chan []byte, 1024*16),
		DataChannel:   make(chan *SctpData, 16),
	}
	sctp.udata = unsafe.Pointer(s)
	return s, nil
}

func (s *SctpTransport) Open() bool {
	bret := C.open_sctp_socket(s.sctp)
	return bool(bret)
}

func (s *SctpTransport) Close() {
	C.usrsctp_close(s.sctp.sock)
	C.usrsctp_deregister_address(unsafe.Pointer(s.sctp))
	s.sctp.sock = nil
}

func (s *SctpTransport) Destroy() {
	C.usrsctp_close(s.sctp.sock)
	C.usrsctp_deregister_address(unsafe.Pointer(s.sctp))
	C.free(unsafe.Pointer(s.sctp))
	s.sctp = nil
	//C.release_usrsctp()
}

//export go_sctp_data_ready_cb
func go_sctp_data_ready_cb(sctp *C.sctp_transport, data unsafe.Pointer, length C.size_t) {
	s := (*SctpTransport)(sctp.udata)
	b := C.GoBytes(data, C.int(length))
	//log.Println("[SCTP] send(out):", len(b))
	s.BufferChannel <- b
}

//export go_sctp_data_received_cb
func go_sctp_data_received_cb(sctp *C.sctp_transport, data unsafe.Pointer, length C.size_t, sid, ppid C.int) {
	s := (*SctpTransport)(sctp.udata)
	b := C.GoBytes(data, C.int(length))
	//log.Println("[SCTP] recv data(in):", len(b))
	d := &SctpData{int(sid), int(ppid), b}
	s.DataChannel <- d
}

//export go_sctp_notification_received_cb
func go_sctp_notification_received_cb(sctp *C.sctp_transport, data unsafe.Pointer, length C.size_t) {
	// TODO: add interested events
	//b := C.GoBytes(data, C.int(length))
	//log.Println("[SCTP] recv notify(int):", len(b))
}

//export go_debug_sctp_printf
func go_debug_sctp_printf(cstr *C.char) {
	log.Println("[SCTP] debug:", C.GoString(cstr))
}

func (s *SctpTransport) Feed(data []byte) {
	s.Lock()
	defer s.Unlock()
	C.usrsctp_conninput(unsafe.Pointer(s.sctp), unsafe.Pointer(&data[0]), C.size_t(len(data)), 0)
}

func (s *SctpTransport) Send(data []byte, ordered bool) (int, error) {
	s.Lock()
	defer s.Unlock()

	param := C.new_send_param(0, C.DMT_BINARY, C.bool(ordered))
	rv := C.send_sctp(s.sctp, unsafe.Pointer(&data[0]), C.size_t(len(data)), param)
	C.free(unsafe.Pointer(param))
	if rv < 0 {
		// TODO should queuing BLOCK packets
		return int(rv), errors.New("fail to send SCTP data")
	}
	return int(rv), nil
}

func (s *SctpTransport) Send2(data []byte, sid, ppid int) (int, error) {
	s.Lock()
	defer s.Unlock()
	rv := C.send_sctp2(s.sctp, unsafe.Pointer(&data[0]), C.size_t(len(data)),
		C.uint16_t(sid), C.uint32_t(ppid))
	if rv < 0 {
		return 0, errors.New("fail to send SCTP data")
	}
	return int(rv), nil
}

func (s *SctpTransport) Connect(port int) error {
	if !s.ready {
		return errors.New("sctp not ready")
	}

	if !s.Open() {
		return errors.New("fail to create SCTP socket")
	}

	s.remotePort = port

	//log.Println("[SCTP] Connect socket=", s.sctp.sock, s.localPort, s.remotePort)
	rv := C.connect_sctp(s.sctp, C.int(s.localPort), C.int(port))
	if rv != 0 {
		s.Close()
		//log.Println("[SCTP] Connect errno=", rv)
		return errors.New("fail to connect SCTP transport")
	}
	return nil
}

// This is for real sctp connection.
func (s *SctpTransport) Accept() error {
	if !s.ready {
		return errors.New("sctp not ready")
	}

	if !s.Open() {
		return errors.New("fail to create SCTP socket")
	}

	rv := C.accept_sctp(s.sctp, C.int(s.localPort))
	if rv < 0 {
		s.Close()
		return errors.New("fail to accept SCTP transport")
	}
	return nil
}

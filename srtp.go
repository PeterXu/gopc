package gopc

/*
#cgo pkg-config: libsrtp2

#include <srtp2/srtp.h>
#include <stdbool.h>
#include <string.h>

#define kSrtpDefaultWindowSize 1024

enum {
  CS_UNKNOWN = 0,
  CS_AES_CM_128_HMAC_SHA1_80 = 1,
  CS_AES_CM_128_HMAC_SHA1_32 = 2,
};

static bool s_srtp_inited_ = false;

extern void go_on_srtp_event(srtp_event_data_t*ev);

static void on_srtp_event(srtp_event_data_t* ev) {
  go_on_srtp_event(ev);
}

static void init_srtp() {
  if (!s_srtp_inited_) {
    srtp_err_status_t err = srtp_init();
    if (err == srtp_err_status_ok) {
      srtp_install_event_handler(on_srtp_event);
      s_srtp_inited_ = true;
    }
  }
}

static void uninit_srtp(srtp_t ctx) {
  if (ctx) {
    srtp_dealloc(ctx);
  }
}

static bool init_srtp_policy(srtp_policy_t *policy, int cs, int ssrc_type, void *master_key) {
  memset(policy, 0, sizeof(srtp_policy_t));
  if (cs == CS_AES_CM_128_HMAC_SHA1_80) {
    srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy->rtp);
    srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy->rtcp);
  }else if (cs == CS_AES_CM_128_HMAC_SHA1_32) {
    srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(&policy->rtp);   // rtp 32,
    srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy->rtcp);  // rtcp 80
  }else {
    return false;
  }

  // key len should be SRTP_MASTER_KEY_LEN
  policy->ssrc.type = ssrc_type;
  policy->ssrc.value = 0;
  policy->key = (unsigned char*)master_key;
  policy->window_size = kSrtpDefaultWindowSize;
  policy->allow_repeat_tx = 1;
  policy->next = NULL;
  return true;
}

static srtp_t set_srtp_key(srtp_t ctx, int cs, int type, void *key) {
  srtp_policy_t policy;
  if (init_srtp_policy(&policy, cs, type, key)) {
    if (ctx) {
      srtp_dealloc(ctx);
    }
    srtp_t new_ctx;
    srtp_err_status_t err = srtp_create(&new_ctx, &policy);
    if (err == srtp_err_status_ok) {
      return new_ctx;
    }
  }
  return NULL;
}

static srtp_t set_srtp_send_key(srtp_t ctx, int cs, void *key) {
  return set_srtp_key(ctx, cs, ssrc_any_outbound, key);
}

static srtp_t set_srtp_recv_key(srtp_t ctx, int cs, void *key) {
  return set_srtp_key(ctx, cs, ssrc_any_inbound, key);
}

static int protect_rtp_rtcp(srtp_t ctx, void* in_data, int in_len, bool is_rtp) {
  if (!ctx) {
    return 0;
  }

  int out_len = in_len;
  srtp_err_status_t err;
  if (is_rtp) {
    err = srtp_protect(ctx, in_data, &out_len);
  }else {
    err = srtp_protect_rtcp(ctx, in_data, &out_len);
  }
  if (err != srtp_err_status_ok) {
    // srtp_err_status_replay_old/srtp_err_status_replay_fail
    return 0-err;
  }
  return out_len;
}

static int protect_rtp(srtp_t ctx, void* in_data, int in_len) {
  return protect_rtp_rtcp(ctx, in_data, in_len, true);
}

static int protect_rtcp(srtp_t ctx, void* in_data, int in_len) {
  return protect_rtp_rtcp(ctx, in_data, in_len, false);
}

static int unprotect_rtp_rtcp(srtp_t ctx, void* in_data, int in_len, bool is_rtp) {
  if (!ctx) {
    return 0;
  }

  int out_len = in_len;
  srtp_err_status_t err;
  if (is_rtp) {
    err = srtp_unprotect(ctx, in_data, &out_len);
  }else {
    err = srtp_unprotect_rtcp(ctx, in_data, &out_len);
  }
  if (err != srtp_err_status_ok) {
    return 0-err;
  }
  return out_len;
}

static int unprotect_rtp(srtp_t ctx, void* in_data, int in_len) {
  return unprotect_rtp_rtcp(ctx, in_data, in_len, true);
}

static int unprotect_rtcp(srtp_t ctx, void* in_data, int in_len) {
  return unprotect_rtp_rtcp(ctx, in_data, in_len, false);
}

*/
import "C"

import (
	"log"
	"unsafe"
)

func init() {
	C.init_srtp()
}

// One Srtp instance can only be used for one session once.
// That means that you should create two for send and recv seperately.

type Srtp struct {
	key     []byte
	cs      C.int
	session C.srtp_t
}

func NewSrtp() *Srtp {
	return &Srtp{
		cs: C.CS_AES_CM_128_HMAC_SHA1_80,
	}
}

func (s *Srtp) Destroy() {
	C.uninit_srtp(s.session)
	s.session = nil
}

//export go_on_srtp_event
func go_on_srtp_event(ev *C.srtp_event_data_t) {
	log.Println("[SRTP] event=", ev.event)
	switch ev.event {
	case C.event_ssrc_collision:
	case C.event_key_soft_limit:
	case C.event_key_hard_limit:
	case C.event_packet_index_limit:
	default:
	}
}

func (s *Srtp) SetSendKey(key []byte) bool {
	s.session = C.set_srtp_send_key(s.session, s.cs, unsafe.Pointer(&key[0]))
	if s.session != nil {
		s.key = make([]byte, len(key))
		copy(s.key, key)
		return true
	}
	return false
}

func (s *Srtp) SetRecvKey(key []byte) bool {
	s.session = C.set_srtp_recv_key(s.session, s.cs, unsafe.Pointer(&key[0]))
	if s.session != nil {
		s.key = make([]byte, len(key))
		copy(s.key, key)
		return true
	}
	return false
}

// Assure len(data) >= size + 20
func (s *Srtp) ProtectRtp(data []byte, size int) int {
	ret := C.protect_rtp(s.session, unsafe.Pointer(&data[0]), C.int(size))
	return int(ret)
}

// Assure len(data) >= size + 20
func (s *Srtp) ProtectRtcp(data []byte, size int) int {
	ret := C.protect_rtcp(s.session, unsafe.Pointer(&data[0]), C.int(size))
	return int(ret)
}

// Return actual data size if ok
func (s *Srtp) UnProtectRtp(data []byte) int {
	ret := C.unprotect_rtp(s.session, unsafe.Pointer(&data[0]), C.int(len(data)))
	return int(ret)
}

// Return actual data size if ok
func (s *Srtp) UnProtectRtcp(data []byte) int {
	ret := C.unprotect_rtcp(s.session, unsafe.Pointer(&data[0]), C.int(len(data)))
	return int(ret)
}

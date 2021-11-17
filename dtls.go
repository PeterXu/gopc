// Based-on https://github.com/xhs/godtls
package gopc

/*
#cgo pkg-config: openssl
#cgo CFLAGS: -Wno-deprecated -std=c99

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>

//#define HAVE_DTLS_SETTIMEOUT
#define SHA256_FINGERPRINT_SIZE (95 + 1)
#define BUFFER_SIZE (1 << 16)

#if (OPENSSL_VERSION_NUMBER >= 0x10101000L)
#define SSL_ST_OK TLS_ST_OK
#define SSL_state SSL_stateless
#endif

static bool SSL_is_init_done(SSL *a) {
  return (SSL_state(a) == SSL_ST_OK);
}

// load crt/key
static int load_key_cert(const char *server_pem, const char *server_key, const char *password,
    X509 **certificate, EVP_PKEY **private_key)
{
  FILE *f = NULL;

  f = fopen(server_pem, "r");
  if (!f) {
    goto error;
  }
  *certificate = PEM_read_X509(f, NULL, NULL, NULL);
  if (!*certificate) {
    goto error;
  }
  fclose(f);

  f = fopen(server_key, "r");
  if (!f) {
    goto error;
  }
  *private_key = PEM_read_PrivateKey(f, NULL, NULL, (void *)password);
  if (!*private_key) {
    goto error;
  }
  fclose(f);

  return 0;

error:
  if (*certificate) {
    X509_free(*certificate);
    *certificate = NULL;
  }
  if (*private_key) {
    EVP_PKEY_free(*private_key);
    *private_key = NULL;
  }
  return -1;
}

static EVP_PKEY *gen_key() {
  EVP_PKEY *pkey = EVP_PKEY_new();
  BIGNUM *exponent = BN_new();
  RSA *rsa = RSA_new();
  if (!pkey || !exponent || !rsa ||
      !BN_set_word(exponent, 0x10001) || // 65537
      !RSA_generate_key_ex(rsa, 1024, exponent, NULL) ||
      !EVP_PKEY_assign_RSA(pkey, rsa)) {
    EVP_PKEY_free(pkey);
    BN_free(exponent);
    RSA_free(rsa);
    return NULL;
  }
  BN_free(exponent);
  return pkey;
}

static X509 *gen_cert(EVP_PKEY* pkey, const char *common, int days) {
  X509 *x509 = NULL;
  BIGNUM *serial_number = NULL;
  X509_NAME *name = NULL;

  if ((x509 = X509_new()) == NULL)
    return NULL;

  if (!X509_set_pubkey(x509, pkey))
    return NULL;

  ASN1_INTEGER* asn1_serial_number;
  if ((serial_number = BN_new()) == NULL ||
      !BN_pseudo_rand(serial_number, 64, 0, 0) ||
      (asn1_serial_number = X509_get_serialNumber(x509)) == NULL ||
      !BN_to_ASN1_INTEGER(serial_number, asn1_serial_number))
    goto cert_err;

  if (!X509_set_version(x509, 0L)) // version 1
    goto cert_err;

  if ((name = X509_NAME_new()) == NULL ||
      !X509_NAME_add_entry_by_NID(
          name, NID_commonName, MBSTRING_UTF8,
          (unsigned char*)common, -1, -1, 0) ||
      !X509_set_subject_name(x509, name) ||
      !X509_set_issuer_name(x509, name))
    goto cert_err;

  if (!X509_gmtime_adj(X509_get_notBefore(x509), 0) ||
      !X509_gmtime_adj(X509_get_notAfter(x509), days * 24 * 3600))
    goto cert_err;

  if (!X509_sign(x509, pkey, EVP_sha1()))
    goto cert_err;

  if (0) {
cert_err:
    X509_free(x509);
    x509 = NULL;
  }
  BN_free(serial_number);
  X509_NAME_free(name);

  return x509;
}

// ssl init
static bool s_ssl_inited_ = false;

void init_ssl() {
  if (!s_ssl_inited_) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    s_ssl_inited_ = true;
  }
}

// dtls context
typedef struct {
  SSL_CTX *ctx;
  uint32_t dtls_timeout_base;
  char fp[SHA256_FINGERPRINT_SIZE];
} dtls_context;

static int verify_peer_certificate_cb(int ok, X509_STORE_CTX *ctx) {
  return 1;
}

static void ssl_info_callback(const SSL* s, int where, int ret) {
}

dtls_context *new_dtls_context(const char *common, int days,
    const char *server_pem, const char* server_key, const char *password) {
  dtls_context *context = (dtls_context *)calloc(1, sizeof *context);
  if (context == NULL)
    return NULL;

  // default server
  SSL_CTX *ctx = SSL_CTX_new(DTLSv1_server_method());
  if (ctx == NULL)
    goto ctx_err;
  context->ctx = ctx;

  SSL_CTX_set_info_callback(ctx, ssl_info_callback);

  int mode = SSL_VERIFY_NONE;
  bool client_auth_enabled = false;
  if (client_auth_enabled) {
    // Require a certificate from the client.
    // Note: Normally this is always true in production, but it may be disabled
    // for testing purposes (e.g. SSLAdapter unit tests).
    mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
  }
  SSL_CTX_set_verify(ctx, mode, verify_peer_certificate_cb);
  SSL_CTX_set_verify_depth(ctx, 4);

  // Select list of available ciphers.
  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);
  SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);

  const char ssl_ciphers[] =
    "ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:RSA+AESGCM:RSA+AES:!aNULL:!MD5:!DSS";
  SSL_CTX_set_cipher_list(ctx, ssl_ciphers);

  const char srtp_ciphers[] = "SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32";
  SSL_CTX_set_tlsext_use_srtp(ctx, srtp_ciphers);

  SSL_CTX_set_read_ahead(ctx, 1); // for DTLS

  // Load crt/key
  EVP_PKEY *key = NULL;
  X509 *cert = NULL;
  if (!server_pem && !server_key) {
    if (common == NULL)
      goto ctx_err;

    key = gen_key();
    if (key == NULL)
      goto ctx_err;

    cert = gen_cert(key, common, days);
    if (cert == NULL)
      goto ctx_err;
  }else if (!server_pem || !server_key) {
    goto ctx_err;
  }else if (load_key_cert(server_pem, server_key, password, &cert, &key) != 0){
    goto ctx_err;
  }

  SSL_CTX_use_PrivateKey(ctx, key);
  SSL_CTX_use_certificate(ctx, cert);

  if (SSL_CTX_check_private_key(ctx) != 1)
    goto ctx_err;

  unsigned int len;
  unsigned char buf[BUFFER_SIZE];
  X509_digest(cert, EVP_sha256(), buf, &len);

  char *p = context->fp;
  for (int i = 0; i < len; ++i) {
    snprintf(p, 4, "%02X:", buf[i]);
    p += 3;
  }
  *(p - 1) = 0;

  if (0) {
ctx_err:
    SSL_CTX_free(ctx);
    free(context);
    context = NULL;
  }

  return context;
}

void destroy_dtls_context(dtls_context *context) {
  if (context != NULL) {
    SSL_CTX_free(context->ctx);
    free(context);
    context = NULL;
  }
}

// dtls transport
typedef struct {
  SSL *ssl;
  BIO *ibio;
  BIO *obio;
} dtls_transport;

static void ssl_dtls_callback(const SSL *ssl, int where, int ret) {
  if(!(where & SSL_CB_ALERT)) {
    return;
  }

  dtls_transport *dtls = SSL_get_ex_data(ssl, 0);
  if (!dtls) {
    return;
  }
}

dtls_transport *new_dtls_transport(dtls_context *context)
{
  dtls_transport *dtls = (dtls_transport *)calloc(1, sizeof *dtls);
  if (dtls == NULL)
    return NULL;

  SSL *ssl = SSL_new(context->ctx);
  if (ssl == NULL)
    goto trans_err;
  dtls->ssl = ssl;

  // TODO
  SSL_set_ex_data(dtls->ssl, 0, dtls);
  SSL_set_info_callback(dtls->ssl, ssl_dtls_callback);

  BIO *bio = BIO_new(BIO_s_mem());
  if (bio == NULL)
    goto trans_err;
  BIO_set_mem_eof_return(bio, -1);
  dtls->ibio = bio;

  bio = BIO_new(BIO_s_mem());
  if (bio == NULL)
    goto trans_err;
  BIO_set_mem_eof_return(bio, -1);
  dtls->obio = bio;

  SSL_set_bio(dtls->ssl, dtls->ibio, dtls->obio);

  EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  //long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION | SSL_OP_SINGLE_ECDH_USE;
  long flags = SSL_OP_SINGLE_ECDH_USE;
  SSL_set_options(dtls->ssl, flags);
  SSL_set_tmp_ecdh(dtls->ssl, ecdh);
  EC_KEY_free(ecdh);

#ifdef HAVE_DTLS_SETTIMEOUT
  DTLSv1_set_initial_timeout_duration(dtls->ssl, context->dtls_timeout_base);
#endif

  if (0) {
trans_err:
    SSL_free(ssl);
    free(dtls);
    dtls = NULL;
  }

  return dtls;
}

#define SRTP_MASTER_KEY_KEY_LEN     16
#define SRTP_MASTER_KEY_SALT_LEN    14

bool export_srtp_keying_material(dtls_transport *dtls, void* result, int result_len) {
  const char kDtlsSrtpExporterLabel[] = "EXTRACTOR-dtls_srtp";
  const uint8_t* context = NULL;
  size_t context_len = 0;
  bool use_context = false;

  int i = SSL_export_keying_material(dtls->ssl, result, result_len,
                                     kDtlsSrtpExporterLabel, strlen(kDtlsSrtpExporterLabel),
                                     context, context_len, use_context);
  if (i != 1) {
    return false;
  }
  return true;
}

void destroy_dtls_transport(dtls_transport *dtls) {
  if (dtls != NULL) {
    SSL_free(dtls->ssl);
    free(dtls);
    dtls = NULL;
  }
}

*/
import "C"

import (
	"errors"
	"log"
	"sync"
	"time"
	"unsafe"
)

func init() {
	C.init_ssl()
}

type DtlsContext struct {
	ctx *C.dtls_context
}

func NewContext(common string, days int) (*DtlsContext, error) {
	s := C.CString(common)
	defer C.free(unsafe.Pointer(s))

	ctx := C.new_dtls_context(s, C.int(days), nil, nil, nil)
	if ctx == nil {
		return nil, errors.New("fail to create DTLS context")
	}
	return &DtlsContext{ctx}, nil
}

func NewContextEx(pem, key, passwd string) (*DtlsContext, error) {
	cpem := C.CString(pem)
	defer C.free(unsafe.Pointer(cpem))
	ckey := C.CString(key)
	defer C.free(unsafe.Pointer(ckey))
	cpasswd := C.CString(passwd)
	defer C.free(unsafe.Pointer(cpasswd))

	ctx := C.new_dtls_context(nil, 0, cpem, ckey, cpasswd)
	if ctx == nil {
		return nil, errors.New("fail to create DTLS context")
	}
	return &DtlsContext{ctx}, nil
}

func (c *DtlsContext) Destroy() {
	C.destroy_dtls_context(c.ctx)
	c.ctx = nil
}

func (c *DtlsContext) NewTransport() (*DtlsTransport, error) {
	dtls := C.new_dtls_transport(c.ctx)
	if dtls == nil {
		return nil, errors.New("fail to create DTLS transport")
	}
	fingerprint := C.GoString(&c.ctx.fp[0])
	log.Println("[DTLS] self fingerprint=", fingerprint)
	t := &DtlsTransport{
		dtls:        dtls,
		Method:      "sha256",
		Fingerprint: fingerprint,
	}
	return t, nil
}

// dtls handshake: incoming data -> BIO_write -> SSL_read
// dtls sending: SSL_write
type DtlsTransport struct {
	dtls          *C.dtls_transport
	Method        string
	Fingerprint   string
	handshakeDone bool
	sync.Mutex
}

func (t *DtlsTransport) Destroy() {
	C.destroy_dtls_transport(t.dtls)
	t.dtls = nil
}

func (t *DtlsTransport) SetConnectState() {
	C.SSL_set_connect_state(t.dtls.ssl)
}

func (t *DtlsTransport) SetAcceptState() {
	C.SSL_set_accept_state(t.dtls.ssl)
}

func (t *DtlsTransport) handshake() {
	t.Lock()
	defer t.Unlock()
	C.SSL_do_handshake(t.dtls.ssl)
}

func (t *DtlsTransport) Handshake() error {
	var err error
	tick := time.Tick(4 * time.Millisecond)
	tickTimeout := time.Tick(15 * time.Second)

	for {
		select {
		case <-tick:
			t.handshake()
			if !C.SSL_is_init_done(t.dtls.ssl) {
				continue
			}
			t.handshakeDone = true
		case <-tickTimeout:
			err = errors.New("DTLS handshake timeout")
		}
		break
	}
	return err
}

func (t *DtlsTransport) Write(data []byte) (int, error) {
	t.Lock()
	defer t.Unlock()
	n := C.SSL_write(t.dtls.ssl, unsafe.Pointer(&data[0]), C.int(len(data)))
	if n < 0 {
		return 0, errors.New("fail to write DTLS data")
	}
	return int(n), nil
}

func (t *DtlsTransport) Read(buf []byte) (int, error) {
	t.Lock()
	defer t.Unlock()
	n := C.SSL_read(t.dtls.ssl, unsafe.Pointer(&buf[0]), C.int(len(buf)))
	if n < 0 {
		return 0, errors.New("fail to read DTLS data")
	}
	return int(n), nil
}

func (t *DtlsTransport) Feed(data []byte) (int, error) {
	t.Lock()
	defer t.Unlock()
	n := C.BIO_write(t.dtls.ibio, unsafe.Pointer(&data[0]), C.int(len(data)))
	if n < 0 {
		return 0, errors.New("fail to feed DTLS data")
	}
	return int(n), nil
}

func (t *DtlsTransport) Spew(buf []byte) (int, error) {
	if C.BIO_ctrl_pending(t.dtls.obio) <= 0 {
		return 0, errors.New("no pending data")
	}

	t.Lock()
	defer t.Unlock()
	n := C.BIO_read(t.dtls.obio, unsafe.Pointer(&buf[0]), C.int(len(buf)))
	if n < 0 {
		return 0, errors.New("spew no data")
	}
	return int(n), nil
}

func (t *DtlsTransport) ExportKeyingMaterial() ([]byte, error) {
	keylen := int(C.SRTP_MASTER_KEY_KEY_LEN*2 + C.SRTP_MASTER_KEY_SALT_LEN*2)
	keying := make([]byte, keylen)
	ret := C.export_srtp_keying_material(t.dtls, unsafe.Pointer(&keying[0]), C.int(keylen))
	if ret {
		return keying, nil
	} else {
		return nil, errors.New("fail to export srtp keying")
	}
}

// @return sendKey,recvKey,error
func (t *DtlsTransport) ExportSrtpKeyPair() ([]byte, []byte, error) {
	keying, err := t.ExportKeyingMaterial()
	if err != nil {
		return nil, nil, err
	}

	//format: "client_key,server_key,client_salt,server_salt"
	//log.Println("[DTLS] keying:", keying)

	const masterLen = int(C.SRTP_MASTER_KEY_KEY_LEN)
	const saltLen = int(C.SRTP_MASTER_KEY_SALT_LEN)
	const keylen = masterLen + saltLen

	client_write_key := make([]byte, keylen)
	server_write_key := make([]byte, keylen)

	offset := 0
	copy(client_write_key, keying[offset:offset+masterLen])

	offset += masterLen
	copy(server_write_key, keying[offset:offset+masterLen])

	offset += masterLen
	copy(client_write_key[masterLen:], keying[offset:offset+saltLen])

	offset += saltLen
	copy(server_write_key[masterLen:], keying[offset:offset+saltLen])

	//log.Println("[DTLS] send:", server_write_key, ", recv:", client_write_key)

	return server_write_key, client_write_key, nil
}

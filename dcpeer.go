// Based-on https://github.com/xhs/gortcdc
package gopc

import (
	"errors"
	"log"
	"strconv"
	"strings"
	"time"

	util "github.com/PeterXu/goutil"
)

const (
	dcRoleClient = 0
	dcRoleServer = 1

	dcStateClosed     = 0
	dcStateConnecting = 1
	dcStateConnected  = 2
)

type SctpPacket struct {
	data    []byte
	ordered bool
}

type DcConnSink interface {
	// Dtls handshake status
	OnDtlsStatus(err error, id string)

	// Sctp connection status
	OnSctpStatus(err error, id string)

	// Sctp data: remote -> sctp-engine -> here
	OnSctpData(data []byte, id string)

	// Rtp data: remote -> srtp-engine -> here
	OnRtpRtcpData(data []byte, id string)

	// Send data to remote directly(called by dtls-engine/sctp-engine)
	ToSendData(data []byte, id string) bool
}

// datachannel peer
type DcPeer struct {
	TAG        string
	id         string
	ctx        *DtlsContext     // dtls ctx
	dtls       *DtlsTransport   // dtls transport
	dtlsCh     chan []byte      // dtls recv chan
	sctp       *SctpTransport   // sctp transport
	sctpCh     chan *SctpPacket // sctp send chan
	role       int              // dc role: client/server
	remotePort int              // dc port(not ip-port)
	state      int              // dc state
	srtpCh     chan []byte      // srtp send chan
	srtpSend   *Srtp            // srtp send session
	srtpRecv   *Srtp            // srtp recv session
	exitTick   chan bool
}

func NewDcPeer(id, pem, key, passwd string) (*DcPeer, error) {
	ctx, err := NewContextEx(pem, key, passwd)
	if err != nil {
		return nil, err
	}
	dtls, err := ctx.NewTransport()
	if err != nil {
		ctx.Destroy()
		return nil, err
	}
	sctp, err := NewSctpTransport()
	if err != nil {
		ctx.Destroy()
		dtls.Destroy()
		return nil, err
	}
	p := &DcPeer{
		TAG:      "[NNET-DC]",
		id:       id,
		ctx:      ctx,
		dtls:     dtls,
		dtlsCh:   make(chan []byte, 64*1024),
		sctp:     sctp,
		sctpCh:   make(chan *SctpPacket, 10),
		srtpCh:   make(chan []byte, 1500),
		role:     dcRoleServer,
		state:    dcStateClosed,
		exitTick: make(chan bool),
	}
	return p, nil
}

func (p *DcPeer) Start(sink DcConnSink) {
	go p.Run(sink)
}

func (p *DcPeer) Destroy() {
	if p.state != dcStateConnected {
		p.Release()
	}
	close(p.exitTick)
}

func (p *DcPeer) Release() {
	if p.dtls != nil {
		p.dtls.Destroy()
		p.dtls = nil
	}
	if p.ctx != nil {
		p.ctx.Destroy()
		p.dtls = nil
	}
	if p.sctp != nil {
		p.sctp.Destroy()
		p.sctp = nil
	}
}

// Dtls recv: remote -> dtls-engine(handshake) -> here
func (p *DcPeer) RecvDtlsPacket(data []byte) {
	p.dtlsCh <- data
}

// Sctp send: here -> sctp-engine -> remote
func (p *DcPeer) SendSctpPacket(data []byte, ordered bool) {
	p.sctpCh <- &SctpPacket{data: data, ordered: ordered}
}

// Srtp send: here -> srtp-engine -> remote
func (p *DcPeer) SendRtpRtcpPacket(data []byte) {
	p.srtpCh <- data
}

func (p *DcPeer) initSrtpSession(send, recv bool) error {
	if sendKey, recvKey, err := p.dtls.ExportSrtpKeyPair(); err == nil {
		log.Println(p.TAG, "Init srtp with keying:", sendKey, recvKey, send, recv)
		if send {
			p.srtpSend = NewSrtp()
			if !p.srtpSend.SetSendKey(sendKey) {
				return errors.New("srtp set send key fail")
			}
		}
		if recv {
			p.srtpRecv = NewSrtp()
			if !p.srtpRecv.SetRecvKey(recvKey) {
				return errors.New("srtp set send key fail")
			}
		}
		return nil
	} else {
		if send {
			p.srtpSend = nil
		}
		if recv {
			p.srtpRecv = nil
		}
		log.Println(p.TAG, "No keying for srtp: ", err)
		return err
	}
}

func (p *DcPeer) waitExit(chans ...chan bool) {
	p.state = dcStateClosed
	for _, ch := range chans {
		<-ch
	}
}

func (p *DcPeer) Run(sink DcConnSink) error {
	defer p.Release()

	if p.role == dcRoleClient {
		log.Println(p.TAG, "DTLS client connecting")
		p.dtls.SetConnectState()
	} else {
		log.Println(p.TAG, "DTLS server accepting")
		p.dtls.SetAcceptState()
	}

	// feed data to dtls/sctp
	dtlsSctpFeedChan := make(chan bool)
	go func() {
		var buf [1 << 16]byte
		for quit := false; !quit; {
			select {
			case data := <-p.dtlsCh:
				//log.Println(p.TAG, "DTLS data feed:", len(data))
				if util.IsDtlsPacket(data) {
					p.dtls.Feed(data)
					if n, _ := p.dtls.Read(buf[:]); n > 0 {
						//log.Println(p.TAG, "SCTP data feed:", n)
						p.sctp.Feed(buf[0:n])
					}
				} else {
					if p.state == dcStateConnected {
						if util.IsRtpRtcpPacket(data) {
							var ret int
							if util.IsRtcpPacket(data) {
								ret = p.srtpRecv.UnProtectRtcp(data)
							} else {
								ret = p.srtpRecv.UnProtectRtp(data)
							}
							if ret > 0 && ret <= len(data) {
								//log.Println(p.TAG, "srtp data, ", ret, len(data))
								sink.OnRtpRtcpData(data[:ret], p.id)
							} else {
								log.Println(p.TAG, "srtp unprotect fail", len(data), ret)
							}
						} else {
							log.Println(p.TAG, "skip not srtp/srtcp packet")
						}
					} else {
						log.Println(p.TAG, "skip packet and not connected")
					}
				}
			case <-p.exitTick:
				//log.Println(p.TAG, "dtls-sctp exiting...")
				close(dtlsSctpFeedChan)
				quit = true
			}
		}
	}()

	// check dtls data
	dtlsSpewChan := make(chan bool)
	go func() {
		var buf [1 << 16]byte
		tick := time.Tick(4 * time.Millisecond)
		for quit := false; !quit; {
			select {
			case <-tick:
				if n, _ := p.dtls.Spew(buf[:]); n > 0 {
					//log.Println(p.TAG, "DTLS(handshake) reply:", n)
					sink.ToSendData(buf[0:n], p.id)
				}
			case <-dtlsSpewChan:
				if n, _ := p.dtls.Spew(buf[:]); n > 0 {
					//log.Println(p.TAG, "DTLS(handshake) exit and flush:", n)
					sink.ToSendData(buf[0:n], p.id)
				}
				//log.Println(p.TAG, "dtls-spew exiting...")
				close(dtlsSpewChan)
				quit = true
			case <-p.exitTick:
				close(dtlsSpewChan)
				quit = true
			}
		}
	}()

	if err := p.dtls.Handshake(); err != nil {
		log.Println(p.TAG, "DTLS handshake error:", err)
		sink.OnDtlsStatus(err, p.id)
		p.waitExit(dtlsSpewChan, dtlsSctpFeedChan)
		return err
	}
	dtlsSpewChan <- true
	log.Println(p.TAG, "DTLS success")
	sink.OnDtlsStatus(nil, p.id)

	// init srtp
	if err := p.initSrtpSession(true, true); err != nil {
		p.waitExit(dtlsSctpFeedChan)
		return err
	}

	// check sctp data
	dtlsSctpWriteChan := make(chan bool)
	go func() {
		var buf [1 << 16]byte
		for quit := false; !quit; {
			select {
			case data := <-p.sctp.BufferChannel:
				//log.Println(p.TAG, "DTLS-SCTP recv:", len(data))
				if data == nil || len(data) == 0 {
					log.Println(p.TAG, "DTLS-SCTP recv empty data")
					continue
				}
				p.dtls.Write(data)

				if n, _ := p.dtls.Spew(buf[:]); n > 0 {
					//log.Println(p.TAG, "DTLS-SCTP reply:", n)
					sink.ToSendData(buf[0:n], p.id)
				}
			case <-p.exitTick:
				//log.Println(p.TAG, "sctp-write exiting...")
				close(dtlsSctpWriteChan)
				quit = true
			}
		}
	}()

	// XXX: Here is SCTP simulate input not real-socket, using Connect(not Accept)
	if err := p.sctp.Connect(p.remotePort); err != nil {
		log.Println(p.TAG, "SCTP Connect error:", err)
		sink.OnSctpStatus(err, p.id)
		p.waitExit(dtlsSctpFeedChan, dtlsSctpWriteChan)
		return err
	}

	log.Println(p.TAG, "SCTP success: role=", p.role)
	p.state = dcStateConnected
	sink.OnSctpStatus(nil, p.id)

	for quit := false; !quit; {
		select {
		case d := <-p.sctp.DataChannel:
			//log.Println(p.TAG, "SCTP recv, sid/ppid/data:", d.Sid, d.Ppid, len(d.Data))
			if d.Ppid >= 51 && d.Ppid <= 54 {
				sink.OnSctpData(d.Data, p.id)
			}
		case pkt := <-p.sctpCh:
			//log.Println(p.TAG, "SCTP send, len=", len(pkt.data))
			ret, err := p.sctp.Send(pkt.data, pkt.ordered)
			log.Println(p.TAG, "SCTP send, ret=", ret, err)
		case data := <-p.srtpCh:
			//log.Println(p.TAG, "SRTP send, ret=", len(data))
			if len(data) <= 1480 && util.IsRtpRtcpPacket(data) {
				var ret int
				buffer, size := util.Clone2(data, len(data)+20)
				if util.IsRtcpPacket(data) {
					ret = p.srtpSend.ProtectRtcp(buffer, size)
				} else {
					ret = p.srtpSend.ProtectRtp(buffer, size)
				}
				if ret > 0 {
					sink.ToSendData(buffer[:ret], p.id)
				} else {
					//log.Println(p.TAG, "srtp protect fail:", len(data), ret)
					if ret != -10 {
						log.Println(p.TAG, "srtp protect fail:", len(data), ret)
						//err := p.initSrtpSession(true, false)
						//log.Println(p.TAG, "srtp protect reinit:", err)
					}
				}
			}
		case <-p.exitTick:
			log.Println(p.TAG, "SCTP exiting...")
			quit = true
		}
	}
	p.waitExit(dtlsSctpFeedChan, dtlsSctpWriteChan)
	log.Println(p.TAG, "SCTP end")

	return nil
}

func (p *DcPeer) ParseOfferSdp(offer string) (int, error) {
	sdps := strings.Split(offer, "\r\n")
	if len(sdps) <= 2 {
		sdps = strings.Split(offer, "\n")
	}
	for i := range sdps {
		// a=sctp-port:5000
		// a=sctpmap:5000 webrtc-datachannel 1024
		if strings.HasPrefix(sdps[i], "a=sctp-port:") || strings.HasPrefix(sdps[i], "a=sctpmap:") {
			sctpmap := strings.Split(sdps[i], " ")[0]
			if port, err := strconv.Atoi(strings.Split(sctpmap, ":")[1]); err != nil {
				return 0, err
			} else {
				p.remotePort = port
			}
		} else if strings.HasPrefix(sdps[i], "a=setup:active") {
			if p.role == dcRoleClient {
				p.role = dcRoleServer
			}
		} else if strings.HasPrefix(sdps[i], "a=setup:passive") {
			if p.role == dcRoleServer {
				p.role = dcRoleClient
			}
		}
	}

	p.state = dcStateConnecting

	return 0, nil
}

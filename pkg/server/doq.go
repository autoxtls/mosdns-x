/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package server

import (
	"context"
	"fmt"
	"net"

	"github.com/quic-go/quic-go"
	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/pkg/dnsutils"
	"github.com/pmkol/mosdns-x/pkg/pool"
	"github.com/pmkol/mosdns-x/pkg/query_context"
	"github.com/pmkol/mosdns-x/pkg/utils"
)

type quicCloser struct {
	conn *quic.Conn
	code quic.ApplicationErrorCode
	desc string
}

func (c *quicCloser) Close() error {
	return c.conn.CloseWithError(c.code, c.desc)
}

func (s *Server) ServeQUIC(conn net.PacketConn) error {
	l, err := s.createQUICListner(conn, []string{"doq"})
	if err != nil {
		return err
	}
	defer l.Close()

	handler := s.opts.DNSHandler
	if handler == nil {
		return errMissingDNSHandler
	}

	if ok := s.trackCloser(l, true); !ok {
		return ErrServerClosed
	}
	defer s.trackCloser(l, false)

	// handle listener
	listenerCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for {
		c, err := l.Accept(listenerCtx)
		if err != nil {
			if s.Closed() {
				return ErrServerClosed
			}
			return fmt.Errorf("unexpected listener err: %w", err)
		}

		// handle connection
		quicConnCtx, cancelConn := context.WithCancel(listenerCtx)
		go func() {
			var errorCode quic.ApplicationErrorCode = 0x0
			var errorString string = "DOQ_NO_ERROR"
			defer c.CloseWithError(errorCode, errorString)
			defer cancelConn()

			closer := &quicCloser{c, 0x1, "DOQ_INTERNAL_ERROR"}
			if !s.trackCloser(closer, true) {
				errorCode = 0x1
				errorString = "DOQ_INTERNAL_ERROR"
				return
			}

			firstReadTimeout := tcpFirstReadTimeout
			idleTimeout := s.opts.IdleTimeout
			if idleTimeout < firstReadTimeout {
				firstReadTimeout = idleTimeout
			}

			clientAddr := utils.GetAddrFromAddr(c.RemoteAddr())
			meta := &query_context.RequestMeta{
				ClientAddr: clientAddr,
			}
			defer s.trackCloser(closer, false)
			for {
				stream, err := c.AcceptStream(quicConnCtx)
				if err != nil {
					select {
					case <-quicConnCtx.Done():
						return
					default:
					}
					continue
				}
				// handle stream
				go func() {
					defer stream.Close()
					req, _, err := dnsutils.ReadMsgFromTCP(stream)
					if err != nil {
						return
					}

					if req.MsgHdr.Id != 0 {
						errorCode = 0x2
						errorString = "DOQ_PROTOCOL_ERROR"
						cancelConn()
						return
					}

					// handle query
					r, err := handler.ServeDNS(quicConnCtx, req, meta)
					if err != nil {
						s.opts.Logger.Warn("handler err", zap.Error(err))
						return
					}

					b, buf, err := pool.PackBuffer(r)
					if err != nil {
						s.opts.Logger.Error("failed to unpack handler's response", zap.Error(err), zap.Stringer("msg", r))
						return
					}
					defer buf.Release()

					if _, err := dnsutils.WriteRawMsgToTCP(stream, b); err != nil {
						s.opts.Logger.Warn("failed to write response", zap.Stringer("client", c.RemoteAddr()), zap.Error(err))
						return
					}
				}()
			}
		}()
	}
}

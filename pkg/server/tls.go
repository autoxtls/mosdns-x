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
	"crypto/tls"
	"errors"
	"net"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/quic-go/quic-go"
	eTLS "gitlab.com/go-extension/tls"
)

func createDynamicCertificate[T tls.Certificate | eTLS.Certificate](certFile string, keyFile string, loader func(certFile string, keyFile string) (T, error)) (*T, error) {
	cert, err := loader(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	c := &cert
	go func() {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			return
		}
		watcher.Add(certFile)
		watcher.Add(keyFile)

		var timer *time.Timer
		for {
			select {
			case e := <-watcher.Events:
				if e.Has(fsnotify.Chmod) || e.Has(fsnotify.Remove) {
					continue
				}
				if timer == nil {
					timer = time.AfterFunc(time.Second, func() {
						timer = nil
						if cert, err := loader(certFile, keyFile); err == nil {
							c = &cert
						}
					})
				} else {
					timer.Reset(time.Second)
				}
			case err := <-watcher.Errors:
				if err != nil {
					return
				}
			}
		}
	}()
	return c, nil
}

func (s *Server) CreateQUICListner(conn net.PacketConn, nextProtos []string) (*quic.EarlyListener, error) {
	if s.opts.Cert == "" || s.opts.Key == "" {
		return nil, errors.New("missing certificate for tls listener")
	}
	cert, err := createDynamicCertificate(s.opts.Cert, s.opts.Key, tls.LoadX509KeyPair)
	if err != nil {
		return nil, err
	}
	return quic.ListenEarly(conn, &tls.Config{
		NextProtos: nextProtos,
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return cert, nil
		},
	}, &quic.Config{
		Allow0RTT:                      true,
		InitialStreamReceiveWindow:     4 * 1024,
		MaxStreamReceiveWindow:         4 * 1024,
		InitialConnectionReceiveWindow: 8 * 1024,
		MaxConnectionReceiveWindow:     64 * 1024,
	})
}

func (s *Server) CreateTLSListner(l net.Listener, nextProtos []string) (net.Listener, error) {
	if s.opts.Cert == "" || s.opts.Key == "" {
		return nil, errors.New("missing certificate for tls listener")
	}
	cert, err := createDynamicCertificate(s.opts.Cert, s.opts.Key, eTLS.LoadX509KeyPair)
	if err != nil {
		return nil, err
	}
	return eTLS.NewListener(l, &eTLS.Config{
		KernelTX:       s.opts.KernelTX,
		KernelRX:       s.opts.KernelRX,
		AllowEarlyData: true,
		NextProtos:     nextProtos,
		GetCertificate: func(chi *eTLS.ClientHelloInfo) (*eTLS.Certificate, error) {
			return cert, nil
		},
	}), nil
}

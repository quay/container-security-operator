package prometheus

import (
	"context"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

type Server struct {
	srv *http.Server
}

func NewServer(addr string) *Server {
	s := &Server{
		srv: &http.Server{
			Addr:    addr,
			Handler: promhttp.Handler(),
		},
	}

	return s
}

func (s *Server) Start() {
	go func() {
		if err := s.srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatal("Failed while serving prometheus: " + err.Error())
		}
	}()
}

func (s *Server) Stop() <-chan error {
	c := make(chan error)

	go func() {
		if err := s.srv.Shutdown(context.Background()); err != nil {
			c <- err
		} else {
			close(c)
		}
	}()

	return c
}

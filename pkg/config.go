package pkg

import (
	"time"
)

type Config struct {
	Version    int
	PeerLimit  int
	AddrLimit  int
	Port       int
	VerTimeout time.Duration
}

func DefaultConfig(port int) *Config {
	c := &Config{
		Version:    0,
		PeerLimit:  20,
		AddrLimit:  1000,
		Port:       port,
		VerTimeout: time.Second * 2,
	}
	return c
}

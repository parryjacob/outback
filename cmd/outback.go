package main

import (
	log "github.com/Sirupsen/logrus"
	"github.com/parryjacob/outback"
)

func main() {
	oa, err := outback.New("config.toml")
	if err != nil {
		log.WithError(err).Fatal("Failed to start Outback!")
	}

	if err := oa.Run(); err != nil {
		log.WithError(err).Fatal("Outback failed")
	}
}

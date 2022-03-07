package main

import (
	"context"
	"flag"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	serverv3 "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	log "github.com/sirupsen/logrus"
	"github.com/wencaiwulue/kubevpn/pkg/control_plane"
	"github.com/wencaiwulue/kubevpn/util"
)

var (
	logger                 *log.Logger
	watchDirectoryFileName string
	port                   uint = 9002
)

func init() {
	logger = log.New()
	log.SetLevel(log.DebugLevel)
	log.SetReportCaller(true)
	log.SetFormatter(&util.Format{})
	flag.StringVar(&watchDirectoryFileName, "watchDirectoryFileName", "/etc/envoy/envoy-config.yaml", "full path to directory to watch for files")
}

func main() {
	snapshotCache := cache.NewSnapshotCache(false, cache.IDHash{}, logger)
	proc := control_plane.NewProcessor(snapshotCache, logger)

	go func() {
		ctx := context.Background()
		server := serverv3.NewServer(ctx, snapshotCache, nil)
		control_plane.RunServer(ctx, server, port)
	}()

	notifyCh := make(chan control_plane.NotifyMessage, 100)

	notifyCh <- control_plane.NotifyMessage{
		Operation: control_plane.Create,
		FilePath:  watchDirectoryFileName,
	}

	go control_plane.Watch(watchDirectoryFileName, notifyCh)

	for {
		select {
		case msg := <-notifyCh:
			log.Infof("path: %s, event: %v", msg.FilePath, msg.Operation)
			proc.ProcessFile(msg)
		}
	}
}

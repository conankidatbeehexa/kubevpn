//go:build !windows
// +build !windows

package util

import (
	"flag"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"

	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/tools/clientcmd"
)

func RunWithElevated() {
	// fix if startup with normal user, after elevated home dir will change to root user in linux
	// but unix don't have this issue
	if runtime.GOOS == "linux" && flag.Lookup("kubeconfig") == nil {
		if _, err := os.Stat(clientcmd.RecommendedHomeFile); err == nil {
			os.Args = append(os.Args, "--kubeconfig", clientcmd.RecommendedHomeFile)
		}
	}
	cmd := exec.Command("sudo", os.Args...)
	log.Debug(cmd.Args)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	// while send single CTRL+C, command will quit immediately, but output will cut off and print util quit final
	// so, mute single CTRL+C, let inner command handle single only
	go func() {
		signals := make(chan os.Signal)
		signal.Notify(signals, os.Interrupt, os.Kill, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGKILL, syscall.SIGSTOP)
		<-signals
	}()
	err := cmd.Run()
	if err != nil {
		log.Warn(err)
	}
}

func IsAdmin() bool {
	return os.Getuid() == 0
}

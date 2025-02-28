//go:build darwin
// +build darwin

package dns

import (
	"context"
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	miekgdns "github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/wencaiwulue/kubevpn/pkg/util"
)

var cancel context.CancelFunc
var resolv = "/etc/resolv.conf"

// SetupDNS support like
// service:port
// service.namespace:port
// service.namespace.svc:port
// service.namespace.svc.cluster:port
// service.namespace.svc.cluster.local:port
func SetupDNS(config *miekgdns.ClientConfig) error {
	usingResolver(config)
	_ = exec.Command("killall", "mDNSResponderHelper").Run()
	_ = exec.Command("killall", "-HUP", "mDNSResponder").Run()
	_ = exec.Command("dscacheutil", "-flushcache").Run()
	return nil
}

func usingResolver(clientConfig *miekgdns.ClientConfig) {
	var err error
	_ = os.RemoveAll(filepath.Join("/", "etc", "resolver"))
	if err = os.MkdirAll(filepath.Join("/", "etc", "resolver"), fs.ModePerm); err != nil {
		log.Error(err)
	}
	config := miekgdns.ClientConfig{
		Servers: clientConfig.Servers,
		Search:  clientConfig.Search,
		Ndots:   5,
		Timeout: 1,
	}
	// for support like: service:port, service.namespace.svc.cluster.local:port
	filename := filepath.Join("/", "etc", "resolver", "local")
	_ = ioutil.WriteFile(filename, []byte(toString(config)), 0644)

	// for support like: service.namespace:port, service.namespace.svc:port, service.namespace.svc.cluster:port
	port := util.GetAvailableUDPPortOrDie()
	go func(port int, clientConfig *miekgdns.ClientConfig) {
		if err = NewDNSServer("udp", "127.0.0.1:"+strconv.Itoa(port), clientConfig); err != nil {
			log.Warnln(err)
		}
	}(port, clientConfig)
	config = miekgdns.ClientConfig{
		Servers: []string{"127.0.0.1"},
		Search:  clientConfig.Search,
		Port:    strconv.Itoa(port),
		Ndots:   clientConfig.Ndots,
		Timeout: 1,
	}
	for _, s := range strings.Split(clientConfig.Search[0], ".") {
		filename = filepath.Join("/", "etc", "resolver", s)
		_ = ioutil.WriteFile(filename, []byte(toString(config)), 0644)
	}
}

func usingNetworkSetup(ip string, namespace string) {
	networkSetup(ip, namespace)
	var ctx context.Context
	ctx, cancel = context.WithCancel(context.TODO())
	go func() {
		ticker := time.NewTicker(time.Second * 10)
		newWatcher, _ := fsnotify.NewWatcher()
		defer newWatcher.Close()
		defer ticker.Stop()
		_ = newWatcher.Add(resolv)
		c := make(chan struct{}, 1)
		c <- struct{}{}
		for {
			select {
			case <-ticker.C:
				c <- struct{}{}
			case /*e :=*/ <-newWatcher.Events:
				//if e.Op == fsnotify.Write {
				c <- struct{}{}
				//}
			case <-c:
				if rc, err := miekgdns.ClientConfigFromFile(resolv); err == nil && rc.Timeout != 1 {
					if !sets.NewString(rc.Servers...).Has(ip) {
						rc.Servers = append(rc.Servers, ip)
						for _, s := range []string{namespace + ".svc.cluster.local", "svc.cluster.local", "cluster.local"} {
							rc.Search = append(rc.Search, s)
						}
						//rc.Ndots = 5
					}
					//rc.Attempts = 1
					rc.Timeout = 1
					_ = ioutil.WriteFile(resolv, []byte(toString(*rc)), 0644)
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

func toString(config miekgdns.ClientConfig) string {
	var builder strings.Builder
	//	builder.WriteString(`#
	//# macOS Notice
	//#
	//# This file is not consulted for DNS hostname resolution, address
	//# resolution, or the DNS query routing mechanism used by most
	//# processes on this system.
	//#
	//# To view the DNS configuration used by this system, use:
	//#   scutil --dns
	//#
	//# SEE ALSO
	//#   dns-sd(1), scutil(8)
	//#
	//# This file is automatically generated.
	//#`)
	//	builder.WriteString("\n")
	if len(config.Search) > 0 {
		builder.WriteString(fmt.Sprintf("search %s\n", strings.Join(config.Search, " ")))
	}
	for i := range config.Servers {
		builder.WriteString(fmt.Sprintf("nameserver %s\n", config.Servers[i]))
	}
	if len(config.Port) != 0 {
		builder.WriteString(fmt.Sprintf("port %s\n", config.Port))
	}
	builder.WriteString(fmt.Sprintf("options ndots:%d\n", config.Ndots))
	builder.WriteString(fmt.Sprintf("options timeout:%d\n", config.Timeout))
	//builder.WriteString(fmt.Sprintf("options attempts:%d\n", config.Attempts))
	return builder.String()
}

func CancelDNS() {
	if cancel != nil {
		cancel()
	}
	_ = os.RemoveAll(filepath.Join("/", "etc", "resolver"))
	//networkCancel()
}

/*
➜  resolver sudo networksetup -setdnsservers Wi-Fi 172.20.135.131 1.1.1.1
➜  resolver sudo networksetup -setsearchdomains Wi-Fi test.svc.cluster.local svc.cluster.local cluster.local
➜  resolver sudo networksetup -getsearchdomains Wi-Fi
test.svc.cluster.local
svc.cluster.local
cluster.local
➜  resolver sudo networksetup -getdnsservers Wi-Fi
172.20.135.131
1.1.1.1
*/
func networkSetup(ip string, namespace string) {
	networkCancel()
	b, err := exec.Command("networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return
	}
	services := strings.Split(string(b), "\n")
	for _, s := range services[:len(services)-1] {
		cmd := exec.Command("networksetup", "-getdnsservers", s)
		output, err := cmd.Output()
		if err == nil {
			var nameservers []string
			if strings.Contains(string(output), "There aren't any DNS Servers") {
				nameservers = make([]string, 0, 0)
				// fix networksetup -getdnsservers is empty, but resolv.conf nameserver is not empty
				if rc, err := miekgdns.ClientConfigFromFile(resolv); err == nil {
					nameservers = rc.Servers
				}
			} else {
				nameservers = strings.Split(string(output), "\n")
				nameservers = nameservers[:len(nameservers)-1]
			}
			// add to tail
			nameservers = append(nameservers, ip)
			args := []string{"-setdnsservers", s}
			output, err = exec.Command("networksetup", append(args, nameservers...)...).Output()
			if err != nil {
				log.Warnf("error while set dnsserver for %s, err: %v, output: %s\n", s, err, string(output))
			}
		}
		output, err = exec.Command("networksetup", "-getsearchdomains", s).Output()
		if err == nil {
			var searchDomains []string
			if strings.Contains(string(output), "There aren't any Search Domains") {
				searchDomains = make([]string, 0, 0)
			} else {
				searchDomains = strings.Split(string(output), "\n")
				searchDomains = searchDomains[:len(searchDomains)-1]
			}
			newSearchDomains := make([]string, len(searchDomains)+3, len(searchDomains)+3)
			copy(newSearchDomains[3:], searchDomains)
			newSearchDomains[0] = fmt.Sprintf("%s.svc.cluster.local", namespace)
			newSearchDomains[1] = "svc.cluster.local"
			newSearchDomains[2] = "cluster.local"
			args := []string{"-setsearchdomains", s}
			bytes, err := exec.Command("networksetup", append(args, newSearchDomains...)...).Output()
			if err != nil {
				log.Warnf("error while set search domain for %s, err: %v, output: %s\n", s, err, string(bytes))
			}
		}
	}
}

func networkCancel() {
	b, err := exec.Command("networksetup", "-listallnetworkservices").CombinedOutput()
	if err != nil {
		return
	}
	services := strings.Split(string(b), "\n")
	for _, s := range services[:len(services)-1] {
		output, err := exec.Command("networksetup", "-getsearchdomains", s).Output()
		if err == nil {
			i := strings.Split(string(output), "\n")
			if i[1] == "svc.cluster.local" && i[2] == "cluster.local" {
				bytes, err := exec.Command("networksetup", "-setsearchdomains", s, strings.Join(i[3:], " ")).Output()
				if err != nil {
					log.Warnf("error while remove search domain for %s, err: %v, output: %s\n", s, err, string(bytes))
				}

				output, err := exec.Command("networksetup", "-getdnsservers", s).Output()
				if err == nil {
					dnsServers := strings.Split(string(output), "\n")
					// dnsServers[len(dnsServers)-1]=""
					// dnsServers[len(dnsServers)-2]="ip which added by KubeVPN"
					dnsServers = dnsServers[:len(dnsServers)-2]
					if len(dnsServers) == 0 {
						// set default dns server to 1.1.1.1 or just keep on empty
						dnsServers = append(dnsServers, "empty")
					}
					args := []string{"-setdnsservers", s}
					combinedOutput, err := exec.Command("networksetup", append(args, dnsServers...)...).Output()
					if err != nil {
						log.Warnf("error while remove dnsserver for %s, err: %v, output: %s\n", s, err, string(combinedOutput))
					}
				}
			}
		}
	}
}

package cmd

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"

	"github.com/spf13/cobra"
)

var RootCmd *cobra.Command

func init() {
	RootCmd = &cobra.Command{
		Use:   "yno <url>",
		Short: "y no server ??",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 1 {
				fmt.Printf("ERROR: You must provide a URL.\n\n")
				RootCmd.Usage()
				os.Exit(1)
			}
			urlStr := args[0]

			u := parse(urlStr)
			checks := runChecks(u)

			fmt.Println()
			fmt.Println("Final report:")
			fmt.Printf("%s Hostname of %s is valid and can be resolved by DNS\n", checko(checks.hostOK), u.Hostname())
			fmt.Printf("%s DNS records for %s lead to this server\n", checko(checks.dnsMatches), u.Hostname())
			fmt.Printf("%s TCP connections can be established on port %s\n", checko(checks.tcpWorks), u.Port())
		},
	}
}

func parse(urlStr string) *url.URL {
	var scheme, host, port string

	if u, err := url.Parse(urlStr); err == nil {
		if u.Scheme != "" && u.Host != "" {
			scheme = u.Scheme
			host = u.Hostname()
			port = u.Port()
		}
	}

	if host == "" {
		if nethost, netport, err := net.SplitHostPort(urlStr); err == nil {
			if validPort(netport) {
				host = nethost
				port = netport
			}
		}
	}

	if host == "" {
		host = urlStr // what else can we do?
	}

	result := &url.URL{
		Scheme: scheme,
		Host:   host,
	}
	if port != "" {
		result.Host = net.JoinHostPort(host, port)
	}

	return result
}

func validPort(port string) bool {
	if port == "" {
		return false
	}
	for _, b := range port {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}

func getExternalIPs() ([]net.IP, error) {
	res, err := http.Get("https://api64.ipify.org")
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	ipStrBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var ips []net.IP

	ip1 := net.ParseIP(string(ipStrBytes))
	if ip1 == nil {
		panic(fmt.Errorf("got bad external IP from ipify: %s", string(ipStrBytes)))
	}
	ips = append(ips, ip1)

	if ip1.To4() == nil {
		// Got an IPv6 address. Make another request to force IPv4.

		res, err := http.Get("https://api.ipify.org")
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()

		ipStrBytes, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, err
		}

		ip2 := net.ParseIP(string(ipStrBytes))
		if ip2 == nil {
			panic(fmt.Errorf("got bad external IP from ipify: %s", string(ipStrBytes)))
		}

		ips = append(ips, ip2)
	}

	return ips, nil
}

type Check int

const (
	CheckUnknown Check = iota
	CheckSuccess
	CheckFail
	CheckWarn
)

type Checks struct {
	hostOK     Check
	dnsMatches Check
	tcpWorks   Check
	udpWorks   Check
	icmpWorks  Check
}

func runChecks(u *url.URL) Checks {
	var res Checks

	fmt.Printf("Looking up host %s...\n", u.Hostname())
	hostAddrs, err := net.LookupHost(u.Hostname())
	if err != nil {
		fmt.Printf("ERROR: could not look up host %s: %v\n", u.Hostname(), err)
		res.hostOK = CheckFail
		return res
	}
	res.hostOK = CheckSuccess

	isLoopback := net.ParseIP(hostAddrs[0]).IsLoopback()
	if !isLoopback {
		fmt.Println("Looking up external IP addresses via ipify.org...")
		externalIPs, err := getExternalIPs()
		if err != nil {
			fmt.Printf("ERROR: failed to get external IP address: %v\n", err)
			return res
		}

		for _, addrString := range hostAddrs {
			addr := net.ParseIP(addrString)
			for _, extIP := range externalIPs {
				if extIP.Equal(addr) {
					res.dnsMatches = CheckSuccess
				}
			}
		}

		if res.dnsMatches != CheckSuccess {
			fmt.Printf("POTENTIAL PROBLEM! None of the addresses for %s matched your external IP addresses.\n", u.Hostname())
			res.dnsMatches = CheckWarn
		}
	}

	if u.Scheme == "" {
		fmt.Println("No protocol was given; assuming TCP")
		u.Scheme = "tcp"
	}

	switch u.Scheme {
	case "tcp", "http", "https":
		// yay tcp, continue
	default:
		fmt.Printf("I do not understand what %s is because I am a jam project :)\n", u.Scheme)
		return res
	}

	if u.Port() == "" {
		fmt.Println("No port was given; assuming port 80")
		u.Host = net.JoinHostPort(u.Host, "80")
	}

	fmt.Printf("Getting a TCP connection to %s...\n", u.Host)
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		fmt.Printf("ERROR: Could not establish TCP connection: %v\n", err)
		res.tcpWorks = CheckFail
		return res
	}
	defer conn.Close()

	fmt.Println("Got a TCP connection.")
	res.tcpWorks = CheckSuccess

	return res
}

func checko(c Check) string {
	switch c {
	case CheckSuccess:
		return "✅"
	case CheckFail:
		return "❌"
	case CheckWarn:
		return "⚠️"
	default:
		return "❓"
	}
}

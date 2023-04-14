package cmd

import (
	"fmt"
	"net"
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
				fmt.Fprintf(os.Stderr, "ERROR: You must provide a URL.\n\n")
				RootCmd.Usage()
				os.Exit(1)
			}
			urlStr := args[0]

			u := parse(urlStr)

			fmt.Printf("Ok I will look up %v\n", u)
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
	} else {
		fmt.Fprintf(os.Stderr, "Could not parse URL: %v\n", err)
	}

	if host == "" {
		if nethost, netport, err := net.SplitHostPort(urlStr); err == nil {
			if validPort(netport) {
				host = nethost
				port = netport
			}
		} else {
			fmt.Fprintf(os.Stderr, "Could not parse host and port: %v\n", err)
		}
	}

	if host == "" {
		host = urlStr // what else can we do?
	}

	fmt.Printf("Scheme: %v\n", scheme)
	fmt.Printf("Host: %v\n", host)
	fmt.Printf("Port: %v\n", port)

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

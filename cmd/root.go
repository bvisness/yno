package cmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bvisness/yno/utils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
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
			report := runChecks(u)

			var programs []ListenInfo
			for _, p := range report.packets {
				if p.Dst.PID == "" {
					continue
				}

				alreadyThere := false
				for _, prog := range programs {
					if prog.PID == p.Dst.PID {
						alreadyThere = true
					}
				}
				if !alreadyThere {
					programs = append(programs, p.Dst)
				}
			}

			if len(programs) > 0 {
				fmt.Println()
				wordPrograms := "programs"
				if len(report.packets) == 1 {
					wordPrograms = "program"
				}
				fmt.Printf("%d %s handled the incoming traffic:\n", len(programs), wordPrograms)
				for _, prog := range programs {
					desc := fmt.Sprintf("PID %s (port %s)", prog.PID, prog.Port)
					if prog.Name != "" {
						desc = fmt.Sprintf("%s (PID %s, port %s)", prog.Name, prog.PID, prog.Port)
					}
					fmt.Printf("- %s\n", desc)
				}
			}

			var packets []YnoPacket
			omittedPackets := 0
			for _, p := range report.packets {
				flags := getTCPFlags(p.TCP)
				if string(p.TCP.Payload) == "" && len(flags) == 1 && flags[0] == "ACK" {
					omittedPackets += 1
				} else {
					packets = append(packets, p)
				}
			}

			if len(report.packets) > 0 {
				fmt.Println()
				fmt.Printf("%d packets were involved in this check (%d omitted here):\n", len(report.packets), omittedPackets)
				for _, p := range packets {
					var srcDescParts []string
					var dstDescParts []string
					if p.Src.Name != "" {
						srcDescParts = append(srcDescParts, p.Src.Name)
					}
					if p.Src.PID != "" {
						srcDescParts = append(srcDescParts, fmt.Sprintf("PID %s", p.Src.PID))
					}
					if p.Dst.Name != "" {
						dstDescParts = append(dstDescParts, p.Dst.Name)
					}
					if p.Dst.PID != "" {
						dstDescParts = append(dstDescParts, fmt.Sprintf("PID %s", p.Dst.PID))
					}

					var srcDesc, dstDesc string
					if len(srcDescParts) > 0 {
						srcDesc = fmt.Sprintf(" (%s)", strings.Join(srcDescParts, ", "))
					}
					if len(dstDescParts) > 0 {
						dstDesc = fmt.Sprintf(" (%s)", strings.Join(dstDescParts, ", "))
					}

					fmt.Printf("- %s:%s%s -> %s:%s%s", p.Src.Host, p.Src.Port, srcDesc, p.Dst.Host, p.Dst.Port, dstDesc)
					if string(p.TCP.Payload) != "" {
						fmt.Println()
						fmt.Print(string(p.TCP.Payload))
						if p.TCP.Payload[len(p.TCP.Payload)-1] != '\n' {
							fmt.Println()
						}
					} else if flags := getTCPFlags(p.TCP); len(flags) > 0 {
						fmt.Printf(" (TCP %s)\n", strings.Join(flags, ", "))
					} else {
						fmt.Printf(" (empty packet)\n")
					}
				}
			}

			fmt.Println()
			fmt.Println("Final report:")
			for _, check := range report.checks {
				printCheck(check)
			}
		},
	}
}

func checkTernary(check CheckStatus, ifOk, ifFail string) string {
	if check == CheckFail {
		return ifFail
	} else {
		return ifOk
	}
}

func printCheck(check Check) {
	var emoji string
	switch check.Status {
	case CheckSuccess:
		emoji = "✅"
	case CheckFail:
		emoji = "❌"
	case CheckWarn:
		emoji = "⚠️"
	default:
		return
	}

	fmt.Printf("%s %s\n", emoji, check.Message)
	for _, detail := range check.Details {
		fmt.Printf("   - %s\n", detail)
	}
}

func getTCPFlags(p *layers.TCP) (flags []string) {
	if p.CWR {
		flags = append(flags, "CWR")
	}
	if p.ECE {
		flags = append(flags, "ECE")
	}
	if p.URG {
		flags = append(flags, "URG")
	}
	if p.ACK {
		flags = append(flags, "ACK")
	}
	if p.PSH {
		flags = append(flags, "PSH")
	}
	if p.RST {
		flags = append(flags, "RST")
	}
	if p.SYN {
		flags = append(flags, "SYN")
	}
	if p.FIN {
		flags = append(flags, "FIN")
	}
	return
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

type CheckStatus int

const (
	CheckUnknown CheckStatus = iota
	CheckSuccess
	CheckFail
	CheckWarn
)

type Check struct {
	Status  CheckStatus
	Message string
	Details []string
}

type Report struct {
	checks  []Check
	packets []YnoPacket
}

func runChecks(u *url.URL) Report {
	var res Report

	fmt.Printf("Looking up host %s...\n", u.Hostname())
	hostAddrs, err := net.LookupHost(u.Hostname())
	if err != nil {
		fmt.Printf("ERROR: could not look up host %s: %v\n", u.Hostname(), err)
		res.checks = append(res.checks, Check{
			Status:  CheckFail,
			Message: fmt.Sprintf("Hostname %s is not valid", u.Hostname()),
		})
		return res
	}
	res.checks = append(res.checks, Check{
		Status:  CheckSuccess,
		Message: fmt.Sprintf("Hostname \"%s\" is valid and can be resolved by DNS", u.Hostname()),
	})
	fmt.Printf("Host is valid.\n")

	isLoopback := net.ParseIP(hostAddrs[0]).IsLoopback()
	var externalIPs []net.IP
	if !isLoopback {
		fmt.Println("Looking up external IP addresses via ipify.org...")
		externalIPs, err = getExternalIPs()
		if err != nil {
			fmt.Printf("ERROR: failed to get external IP address: %v\n", err)
			return res
		}

		dnsMatches := false
		for _, addrString := range hostAddrs {
			addr := net.ParseIP(addrString)
			for _, extIP := range externalIPs {
				if extIP.Equal(addr) {
					dnsMatches = true
					res.checks = append(res.checks, Check{
						Status:  CheckSuccess,
						Message: fmt.Sprintf("DNS records for %s lead to this server", u.Hostname()),
					})
				}
			}
		}

		if !dnsMatches {
			fmt.Printf("POTENTIAL PROBLEM! None of the addresses for %s matched your external IP addresses.\n", u.Hostname())
			res.checks = append(res.checks, Check{
				Status:  CheckWarn,
				Message: fmt.Sprintf("DNS records for %s do not lead to this server", u.Hostname()),
			})
		}
	}

	if u.Scheme == "" {
		fmt.Println("No protocol was given; assuming HTTP")
		u.Scheme = "http"
	}

	switch u.Scheme {
	case "http":
		// yay http, continue
	default:
		fmt.Printf("I do not understand what %s is because I am a jam project :)\n", u.Scheme)
		return res
	}

	if u.Port() == "" {
		fmt.Println("No port was given; assuming port 80")
		u.Host = net.JoinHostPort(u.Host, "80")
	}

	var listeningStatus CheckStatus
	var listeningMessage string

	isListening := len(checkListeningPorts(u.Port())) > 0
	if isListening {
		listeningStatus = CheckSuccess
		listeningMessage = fmt.Sprintf("Server is listening on port %s", u.Port())
	} else {
		fmt.Printf("PROBLEM: Nothing is listening on port %s.\n", u.Port())
		listeningStatus = CheckFail
		listeningMessage = fmt.Sprintf("Server is not listening on port %s", u.Port())
	}

	alsoCheck := ""
	if u.Port() == "80" {
		alsoCheck = "443"
	} else if u.Port() == "443" {
		alsoCheck = "80"
	}
	if alsoCheck != "" {
		if len(checkListeningPorts(alsoCheck)) > 0 {
			if !isListening {
				listeningMessage += fmt.Sprintf(" (but it is listening on port %s)", alsoCheck)
			} else {
				listeningMessage += fmt.Sprintf(" (and port %s)", alsoCheck)
			}
		}
	}

	res.checks = append(res.checks, Check{
		Status:  listeningStatus,
		Message: listeningMessage,
	})

	var tokenBytes [16]byte
	rand.Read(tokenBytes[:])
	for i, b := range tokenBytes {
		const alphabet = "bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ2456789"
		tokenBytes[i] = alphabet[int(b)%len(alphabet)]
	}
	token := string(tokenBytes[:])

	var sourcePorts []layers.TCPPort
	packetsChan, handle := getPackets(func(p gopacket.Packet) bool {
		if tcpLayer := p.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			// Track any packets that have our random token
			if strings.Contains(string(tcp.Payload), token) {
				sourcePorts = append(sourcePorts, tcp.SrcPort)
				return true
			}
			// Track any packets that are replying after receiving the token
			for _, srcPort := range sourcePorts {
				if srcPort == tcp.DstPort {
					return true
				}
			}
		}
		return false
	})
	defer handle.Close()

	var wg sync.WaitGroup
	var packets []gopacket.Packet
	wg.Add(1)
	go func() {
		defer wg.Done()
		for packet := range packetsChan {
			packets = append(packets, packet)
		}
	}()

	fmt.Printf("Making HTTP request to %s...\n", u.Host)
	httpReq, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/", u.Host), nil)
	httpReq.Header.Add("X-ynoserver", token)
	client := http.Client{
		Timeout: time.Second * 5,
		// See https://stackoverflow.com/questions/49384786/how-to-capture-ip-address-of-server-providing-http-response
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := net.Dial(network, addr)
				if err == nil {
					httpReq.RemoteAddr = conn.RemoteAddr().String()
				}
				return conn, err
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			httpReq = req
			return nil
		},
	}
	httpRes, err := client.Do(httpReq)
	if err == nil {
		defer httpRes.Body.Close()
		fmt.Printf("Got HTTP response.\n")
		if httpRes.StatusCode == http.StatusBadGateway {
			fmt.Printf("PROBLEM: Got 502 Bad Gateway response.\n")
			res.checks = append(res.checks, Check{
				Status:  CheckWarn,
				Message: "HTTP requests / responses are working, but got 502 Bad Gateway response",
			})
		} else {
			res.checks = append(res.checks, Check{
				Status:  CheckSuccess,
				Message: "HTTP requests / responses are working",
			})
		}
	} else {
		fmt.Printf("ERROR: HTTP request failed: %v\n", err)
		res.checks = append(res.checks, Check{
			Status:  CheckFail,
			Message: "HTTP requests / responses are not working",
		})
	}

	fmt.Printf("Checking packets...\n")
	time.Sleep(time.Millisecond * 100) // TODO: Great jank, should sniff for the HTTP response instead
	handle.Close()
	wg.Wait()

	port2listener := make(map[string]ListenInfo)
	getListener := func(port string) ListenInfo {
		if l, ok := port2listener[port]; ok {
			return l
		} else {
			listeners := checkListeningPorts(port)
			if len(listeners) == 0 {
				port2listener[port] = ListenInfo{
					Port: port,
				}
			} else {
				port2listener[port] = listeners[0]
			}
			return port2listener[port]
		}
	}

	for _, p := range packets {
		tcp := p.Layer(layers.LayerTypeTCP).(*layers.TCP)
		srcPortStr := strconv.Itoa(int(tcp.SrcPort))
		dstPortStr := strconv.Itoa(int(tcp.DstPort))

		res.packets = append(res.packets, YnoPacket{
			TCP: tcp,
			Src: getListener(srcPortStr),
			Dst: getListener(dstPortStr),
		})
	}

	if httpRes != nil {
		if len(packets) > 0 {
			res.checks = append(res.checks, Check{
				Status:  CheckSuccess,
				Message: "Request arrived at this server",
			})
		} else {
			check := Check{
				Status:  CheckFail,
				Message: "Request never arrived at this server (who are you talking to?)",
			}

			check.Details = append(check.Details, fmt.Sprintf("Request went to %s", httpReq.RemoteAddr))
			// TODO: In theory we should be able to read the source IP address from the response's TCP packets, but golang's HTTP client doesn't want to let us >:(
			// (I realize it could be spoofed or whatever, but the goal is to help people find problems, ok?)

			if len(hostAddrs) > 0 {
				var hostAddrMessage string
				for _, addr := range hostAddrs {
					hostAddrMessage += fmt.Sprintf("\n     - %s", addr)
				}
				check.Details = append(check.Details, fmt.Sprintf("%s resolved to these IP addresses:%s", u.Hostname(), hostAddrMessage))
			}
			if len(externalIPs) > 0 {
				var extIPMessage string
				for _, ip := range externalIPs {
					extIPMessage += fmt.Sprintf("\n     - %s", ip)
				}
				check.Details = append(check.Details, fmt.Sprintf("This server's external IP addresses:%s", extIPMessage))
			}

			res.checks = append(res.checks, check)
		}
	}

	return res
}

var reSSLine = regexp.MustCompile(`LISTEN +\d+ +\d+ +([^ ]+) +[^ ]+( +(.*))?`)
var reSSPName = regexp.MustCompile(`\(\("([^"]+)"`)
var reSSPID = regexp.MustCompile(`pid=(\d+)`)

type ListenInfo struct {
	Host string
	Port string
	PID  string
	Name string
}

type YnoPacket struct {
	TCP      *layers.TCP
	Src, Dst ListenInfo
}

func checkListeningPorts(port string) []ListenInfo {
	cmd := exec.Command("ss", "-tnlHOp", fmt.Sprintf("( sport = :%s )", port))
	var buf bytes.Buffer
	cmd.Stdout = &buf
	utils.Must(cmd.Run())

	var res []ListenInfo

	lines := strings.Split(buf.String(), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		var info ListenInfo

		m := reSSLine.FindStringSubmatch(line)
		if m == nil {
			panic(fmt.Errorf("ss line didn't match the regex: %s", line))
		}
		info.Host, info.Port, _ = net.SplitHostPort(m[1])
		pinfo := m[3]
		if pinfo != "" {
			info.PID = reSSPID.FindStringSubmatch(pinfo)[1]
			info.Name = reSSPName.FindStringSubmatch(pinfo)[1]
		}

		res = append(res, info)
	}

	return res
}

func getPackets(filter func(p gopacket.Packet) bool) (<-chan gopacket.Packet, *pcap.Handle) {
	c := make(chan gopacket.Packet)

	handle, err := pcap.OpenLive("any", 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}

	err = handle.SetBPFFilter("tcp and not outbound")
	if err != nil {
		panic(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	go func() {
		defer close(c)
		for packet := range packetSource.Packets() {
			if filter(packet) {
				c <- packet
			}
		}
	}()

	return c, handle
}

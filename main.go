package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"

	yaml "gopkg.in/yaml.v2"
)

var (
	cidr        string
	scanTimeout int
	scanThreads int
	portStart   int
	portEnd     int
	knPorts     KnownPorts
	hostsRange  []string
)

//UNKNOWN defaul value for unknown port
const UNKNOWN = "<unknown>"

//KnownPorts structur for Describing ports
type KnownPorts struct {
	Services []struct {
		Description string `yaml:"description"`
		Port        int    `yaml:"port"`
	} `yaml:"services"`
}

//PortScanner structur for NewPortScanner fuction
type PortScanner struct {
	host    string
	timeout time.Duration
	threads int
}

type tempInventory struct {
	Host  string `yaml:"host"`
	Ports []int  `yaml:"ports"`
}
type portsInventory struct {
	Ports []int `yaml:"ports"`
}

func init() {
	knPorts = portsFromConfig()
}

func main() {
	flag.StringVar(&cidr, "target", "127.0.0.1", "/ IP address or CIDR or hostname")
	//	Net = flag.String("net", "127.0.0.1/32", "a string / network range")
	flag.IntVar(&scanTimeout, "timeout", 1, "/ time in seconds")
	flag.IntVar(&scanThreads, "threads", 5, "/ parallel connections")
	flag.IntVar(&portStart, "portstart", 20, "/ first port of scanning")
	flag.IntVar(&portEnd, "portend", 65536, "/ last port of scanning")
	flag.Parse()

	fmt.Printf("Scan target is: %s, Timout is: %d, We use %d threads, First port is: %d, Last port is %d\n\n", cidr, scanTimeout, scanThreads, portStart, portEnd)

	var err error
	switch {
	case strings.Contains(cidr, "/"):
		hostsRange, err = getHosts(cidr)
		if err != nil {
			panic(err)
		}
		fmt.Printf("You used CIDR. The Range of hosts looks: %s\n", hostsRange)
	case isLetter(cidr):
		ipaddr, err := net.ResolveIPAddr("ip4", cidr)
		if err != nil {
			panic(err)
		}

		hostsRange = append(hostsRange, ipaddr.String())
		fmt.Printf("You used Hostname. The target ip is: %s\n", hostsRange)
	default:
		hostsRange = append(hostsRange, cidr)
		fmt.Printf("You used single IP. The target ip is: %s\n", hostsRange)
	}

	for _, host := range hostsRange {
		result := scanHost(host, scanTimeout, scanThreads, portStart, portEnd)
		if len(result.Ports) > 0 {
			processingResult(result.Host, result.Ports)
		} else {
			fmt.Printf("Scan has not found opened ports on host %s from port %d to %d, nothing to add into inventory. \n\n", host, portStart, portEnd)
		}

	}
}

func portsFromConfig() KnownPorts {
	var ports KnownPorts
	source, err := ioutil.ReadFile("./knownPorts.yaml")
	if err != nil {
		panic(err)
	}
	err = yaml.Unmarshal(source, &ports)
	if err != nil {
		panic(err)
	}
	return ports
}

func getHosts(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	//remove network address and broadcast address
	return ips[1 : len(ips)-1], nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func isLetter(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) {
			return true
		}
	}
	return false
}

func scanHost(host string, timeout int, threads int, portfirst int, portlast int) tempInventory {
	ps := NewPortScanner(host, time.Duration(timeout)*time.Second, threads)
	fmt.Printf("scanning ports %d-%d on host %s...\n\n", portStart, portEnd, host)

	openedPorts := ps.GetOpenedPort(portStart, portEnd)

	var invent tempInventory
	invent.Host = host
	for i := 0; i < len(openedPorts); i++ {
		port := openedPorts[i]
		invent.Ports = append(invent.Ports, port)

	}

	return invent
}

//NewPortScanner hendler for scanner
func NewPortScanner(host string, timeout time.Duration, threads int) *PortScanner {
	return &PortScanner{host, timeout, threads}
}

//SetThreads - speaks for itself.
func (h *PortScanner) SetThreads(threads int) {
	h.threads = threads
}

//SetTimeout - speaks for itself.
func (h *PortScanner) SetTimeout(timeout time.Duration) {
	h.timeout = timeout
}

//IsOpen connect to ports
func (h PortScanner) IsOpen(port int) bool {
	tcpAddr, err := net.ResolveTCPAddr("tcp4", h.hostPort(port))
	if err != nil {
		return false
	}
	conn, err := net.DialTimeout("tcp", tcpAddr.String(), h.timeout)
	if err != nil {
		return false
	}

	defer conn.Close()

	return true
}

//GetOpenedPort
func (h PortScanner) GetOpenedPort(portStart int, portEnds int) []int {
	rv := []int{}
	l := sync.Mutex{}
	sem := make(chan bool, h.threads)
	for port := portStart; port <= portEnds; port++ {
		sem <- true
		go func(port int) {
			if h.IsOpen(port) {
				l.Lock()
				rv = append(rv, port)
				l.Unlock()
			}
			<-sem
		}(port)
	}
	for i := 0; i < cap(sem); i++ {
		sem <- true
	}
	return rv
}

func (h PortScanner) hostPort(port int) string {
	return fmt.Sprintf("%s:%d", h.host, port)
}

func (h PortScanner) openConn(host string) (net.Conn, error) {
	tcpAddr, err := net.ResolveTCPAddr("tcp4", host)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialTimeout("tcp", tcpAddr.String(), h.timeout)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

//DescribePort get Describetion of ports
func DescribePort(port int) string {
	switch {
	default:
		return UNKNOWN
	case port > 0:
		assumed := predictPort(port, knPorts)
		return assumed
	}
}

func predictPort(port int, data KnownPorts) string {
	description := "UNKNOWN"
	for _, e := range data.Services {
		if e.Port == port {
			description = e.Description
		}
	}
	if len(description) > 0 {
		return description
	}
	return description
}

func processingResult(host string, ports []int) {
	y, err := yaml.Marshal(ports)
	if err != nil {
		panic(err)
	}
	if _, err := os.Stat("inventory/" + host + ".yaml"); os.IsNotExist(err) {
		_, err := os.Create("inventory/" + host + ".yaml")
		if err != nil {
			fmt.Println(err)
		}
		err = ioutil.WriteFile("inventory/"+host+".yaml", y, 0644)
		if err != nil {
			fmt.Println(err)
		}
		for _, p := range ports {
			fmt.Print(" ", p, " [open]")
			fmt.Println("  -->  ", DescribePort(p))
		}
	} else {
		fmt.Printf("Target %s was found in an inventory\n", host)
		check := isResultsEqual(host, ports)
		if check != true {
			fmt.Printf("Something changed on host %s, updating inventory...\n", host)
			err = ioutil.WriteFile("inventory/"+host+".yaml", y, 0644)
			if err != nil {
				fmt.Println(err)

			}
			fmt.Println("New scan found next ports:")
			for _, p := range ports {
				fmt.Print(" ", p, " [open]")
				fmt.Println("  -->  ", DescribePort(p))
			}
		} else {
			fmt.Printf("Nothing changed on host %s since last scan. Please check your file %s.yaml\n", host, host)
		}
	}
}
func isResultsEqual(host string, newPorts []int) bool {
	var oldPorts []int
	source, err := ioutil.ReadFile("inventory/" + host + ".yaml")
	if err != nil {
		panic(err)
	}
	err = yaml.Unmarshal(source, &oldPorts)
	if err != nil {
		panic(err)
	}
	if len(newPorts) == len(oldPorts) {
		return true
	}
	return false
}

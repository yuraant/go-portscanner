# go-portscanner
Console port scanner with flags as configuration.

## Prerequisites for building app
The application uses gopkg.in/yaml.v2 library to manage yaml files. Which use as configuration and store for inventory.
You need to install this library before you build app
```
go get gopkg.in/yaml.v2
```
Another part of application is based on standard Golang libraries.
Build example:
```
# cd [path to app folder]
# go build
```
## Configuration 
Application has configuration file for known ports [knownPorts.yaml](https://github.com/yuraant/go-portscanner/blob/master/knownPorts.yaml). There is list of related services to ports. You can add ports to this list in accordance with the structure of file. These descriptions for ports will be shown when application finds such open ports.
````
#host:go-portscanner$ ./go-portscanner -target 192.168.1.70
Scan target is: 192.168.1.70, Timout is: 1, We use 5 threads, First port is: 20, Last port is 65536

You used single IP. The target IP is: [192.168.1.70]
scanning ports 20-65536 on host 192.168.1.70...

 80 [open]  -->   http
 139 [open]  -->   UNKNOWN
 443 [open]  -->   https
 445 [open]  -->   SMB
 548 [open]  -->   UNKNOWN
 5000 [open]  -->   UNKNOWN
 5001 [open]  -->   UNKNOWN
````
The application has own help for arguments. You can run application with flag -h or -help to show default values and arguments.
````
#host:go-portscanner$ ./go-portscanner -h
Usage of ./go-portscanner:
  -portend int
        / Last port of scanning (default 65536)
  -portstart int
        / First port of scanning (default 20)
  -target string
        / Single IP address or CIDR or hostname (default "127.0.0.1")
  -threads int
        / Parallel connections (default 5)
  -timeout int
        / Time in seconds (default 1)
````

## Inventory
Directory [inventory](https://github.com/yuraant/go-portscanner/tree/master/inventory) will contain yaml files with results of scan in case if scanner found at least one open port

## Examples of using
Hostname
```
#host:go-portscanner$ ./go-portscanner -target google.com
Scan target is: google.com, Timout is: 1, We use 5 threads, First port is: 20, Last port is 65536

You used Hostname. The target IP is: [216.58.214.206]
scanning ports 20-65536 on host 216.58.214.206...
```
Single IP
```
#host:go-portscanner$ ./go-portscanner -target 192.168.1.70
Scan target is: 192.168.1.70, Timout is: 1, We use 5 threads, First port is: 20, Last port is 65536

You used single IP. The target IP is: [192.168.1.70]
scanning ports 20-65536 on host 192.168.1.70...
```
CIDR
````
#host:go-portscanner$ ./go-portscanner -target 192.168.1.70/30
Scan target is: 192.168.1.70/30, Timout is: 1, We use 5 threads, First port is: 20, Last port is 65536

You used CIDR. The Range of hosts looks: [192.168.1.69 192.168.1.70]
scanning ports 20-65536 on host 192.168.1.69...
````
All parameters
````
#host:go-portscanner$ ./go-portscanner -target 192.168.1.70  -threads 10 -timeout 3 -portstart 21 -portend 5000
Scan target is: 192.168.1.70, Timout is: 3, We use 10 threads, First port is: 21, Last port is 5000

You used single IP. The target IP is: [192.168.1.70]
scanning ports 21-5000 on host 192.168.1.70...
````

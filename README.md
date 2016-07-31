timestamp-decoder
=================

This utility decodes the [ExaLINK Fusion](http://exablaze.com/exalink-fusion)
timestamped output stream.  It can capture & decode timestamped traffic
directly using an [ExaNIC](http://exablaze.com/exanic-x10) interface or it
can load in a pcap file.

The ExaLINK Fusion allows any packets flowing through it to be mirrored out
to a port, where timestamping can then be enabled.  In `fcs` or `fcs-compat` modes,
the timestamp format used is replacement of the Ethernet FCS with a 32bit counter
value.  This counter value is based off a 350MHz clock, resulting in a timestamp
resolution of ~2.6ns. In `append` or `append-compat` modes, the counter value
is inserted between the end of the payload and before the FCS.

Every second, The ExaLINK Fusion will send a special packet called a
keyframe, which maps the counter value to nanosecond UTC time.

## Requirements

 * g++ 4.7 or later
 * libpcap-dev
 * exanic-devel

## Building

`make clean all`

## Usage

```shell
$ ./build/timestamp-decoder
Usage: ./build/timestamp-decoder
  --read <arg>    pcap file input, or exanic interface name
  --write <arg>   file for output, - for std out, or ending in .pcap
  --count <arg>   number of records to read, 0 for all
  --date <arg>    date-time format to use for output
  --all           write all packets, including keyframes
  --offset <arg>  hw timestamp offset from the end of packet:
                  4 if the timestamp mode is FCS,
                  8 if the timestamp mode is append
  --ignore-fcs    use this to skip FCS checks
  --verbose, -v   specify more often to be more verbose
  --help,    -h   show this help and exit
```

## Examples

* Read data from exanic0:0 and decode+dump to stdout
(mirror timestamp modes `fcs` or `fcs-compat`):

`$ build/timestamp-decoder --read exanic0:0 --write -`

* Read data from exanic0:0 and decode+write to a pcap file
(mirror timetamp modes `append` or `append-compat`):

`$ build/timestamp-decoder --read exanic0:0 --write decode.pcap --offset 8`

* Capture 60s worth of data from an interface that does not capture FCS,
then decode+dump to stdout (mirror timetamp modes `append` or `append-compat`):

```shell
$ sudo timeout 60 tcpdump -i eth0 -w raw.pcap
$ build/timestamp-decoder --read raw.pcap --write - --ignore-fcs
```

* Configure interface `eth2` to receive frames with a bad FCS, receive 60s
worth of data (mirror timestamp modes `fcs` or `fcs-compat`), then decode & write
out (note not all interfaces will support this ethtool option):

```shell
$ sudo ethtool -K eth2 rx-fcs on
$ sudo ethtool -K eth2 rx-all on
$ sudo timeout 60 tcpdump -i eth2 -w raw.pcap
$ build/timestamp-decoder --read raw.pcap --write decode.pcap
```

* Use verbose mode to diagnose a problem with getting timestamps. You can
see from the packet dump, that the last four bytes match the expected FCS.
In other words the FCS does not contain the timestamp, presumably append
mode was used for timestamping, and so the solution is to run with `--offset 8`

```shell
$ # wrong offset
$ ./build/timestamp-decoder --read test/exa.mode.append.pcap --write /tmp/t.pcap -vvv
options: { verbose:3 read:'test/exa.mode.append.pcap' write:'/tmp/t.pcap' date:'%Y/%m/%d-%H:%M:%S' count:0 all:0 offset:4 fcs:check }
recoverable problem processing record #27 (72 bytes): record_time_missing
    ffffffffffffdead beeffeed08000000 0000000000000000 0000000000000000
    0000400000000000 0100000010111213 1415161718191a1b 1c10111213141516
    f18841ed32aa12f1     fcs=32aa12f1
recoverable problem processing record #28 (72 bytes): record_time_missing
    ffffffffffffdead beeffeed08000000 0000000000000000 0000000000000000
    0000400000000000 0200000020212223 2425262728292a2b 2c20212223242526
    f18842929eb4ba81     fcs=9eb4ba81
recoverable problem processing record #29 (72 bytes): record_time_missing
    ffffffffffffdead beeffeed08000000 0000000000000000 0000000000000000
    0000400000000000 0300000030313233 3435363738393a3b 3c30313233343536
    f1884331339794a1     fcs=339794a1
Packets: read 37, key frames 33, written 0, errors 3
$ # correct offset
$ ./build/timestamp-decoder --read test/exa.mode.append.pcap --write /tmp/t.pcap -vvv --offset 8
options: { verbose:3 read:'test/exa.mode.append.pcap' write:'/tmp/t.pcap' date:'%Y/%m/%d-%H:%M:%S' count:0 all:0 offset:8 fcs:check }
Packets: read 37, key frames 33, written 3, errors 0
```

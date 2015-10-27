timestamp-decoder
=================

This utility decodes the [ExaLINK Fusion](www.exablaze.com.exalink-fusion)  timestamped output stream.  It can capture & decode timestamped traffic directly using an [ExaNIC](http://exablaze.com/exanic-x10) interface or it can load in a pcap file.

The ExaLINK Fusion allows any packets flowing through it to be mirrored out to a port, where timestamping can then be enabled.  The timestamp format used is replacement of the Ethernet FCS with a 32bit counter value.  This counter value is based off a 350MHz clock, resulting in a timestamp resolution of ~2.6ns.  

Every second, The ExaLINK Fusion will send a special packet called a keyframe, which maps the counter value to nanosecond UTC time.

## Requirements

 * g++ 4.7 or later
 * libpcap-dev

## Building

`make`

## Usage

```shell
$ ./build/timestamp-decoder
Usage: ./build/timestamp-decoder
  --read <arg>    pcap file input, or exanic interface name
  --write <arg>   file for output, - for std out, and ending in .pcap
  --count <arg>   number of records to read
  --date <arg>    date-time format to use for output
  --all           write keyframe packets
  --verbose, -v   be verbose
  --help,    -h   show this help and exit
```

## Examples

* Read data from exanic0:0 and decode+dump to stdout:

`$ build/timestamp-decoder --read exanic0:0 --write -`

* Read data from exanic0:0 and decode+write to a pcap file include the :

`$ build/timestamp-decoder --read exanic0:0 --write decode.pcap`

* Configure interface `eth2` to receive frames with a bad FCS, receive 60s worth of data, then decode & write out (note not all interfaces will support this ethtool option):

```shell
$ sudo ethtool -K eth2 rx-fcs on
$ sudo ethtool -K eth2 rx-all on
$ sudo timeout 60 tcpdump -i eth2 -w raw.pcap
$ build/timestamp-decoder --read raw.pcap --write decode.pcap
```
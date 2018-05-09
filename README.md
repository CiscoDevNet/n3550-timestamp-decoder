timestamp-decoder
=================

This utility decodes the [ExaLINK Fusion](http://exablaze.com/exalink-fusion)
and ExaLINK Fusion HPT timestamped output stream.  It can capture & decode
timestamped traffic directly using an [ExaNIC](http://exablaze.com/exanic-x10)
interface or it can load in a pcap file.

The ExaLINK Fusion allows any packets flowing through it to be mirrored out
to a port, where timestamping can then be enabled.  In `fcs` or `fcs-compat` modes,
the timestamp format used is replacement of the Ethernet FCS with a 32bit counter
value.  This counter value is based off a 350MHz clock, resulting in a timestamp
resolution of ~2.8ns. In `append` or `append-compat` modes, the counter value
is inserted between the end of the payload and before the FCS.

Every second, the ExaLINK Fusion will send a special packet called a
keyframe, which maps the counter value to nanosecond UTC time.

This utility also supports decoding of the ExaLINK Fusion HPT timestamp format.
This is a 16 byte trailer appended to each packet which contains a picosecond
resolution timestamp and metadata to identify the source of the packet.

## Requirements

 * g++ 4.7 or later
 * libpcap-dev
 * exanic-devel (only required for capture using an ExaNIC)

## Building

`make clean all`

## Usage

```text
Usage: timestamp-decoder [options]
Built with support for direct ExaNIC capture
Input options:
  --read <arg>      pcap file input, or exanic interface name
  --count <arg>     number of records to read, 0 for all
  --no-promisc, -p  do not attempt to put interface in promiscuous mode

Output options:
  --write <arg>     file for output, - for stdout, or ending in .pcap
  --date <arg>      date-time format to use for output
  --all             write all packets, including keyframes
  --no-payload      don't write packet contents to stdout

Timestamp options:
  --32-bit          parse 32 bit timestamps
  --trailer         parse Exablaze timestamp trailers
  --offset <arg>    timestamp offset from the end of packet
  --no-fix-fcs      don't rewrite 32 bit timestamp with correct FCS

Other options:
  --verbose,    -v  specify more often to be more verbose
  --help,       -h  show this help and exit
```

This utility will attempt to automatically detect the type of timestamp present
in the input stream and the position of the timestamp in the packet.
Automatic detection can be disabled by specifying the timestamp type using the
`--32-bit` or `--trailer` options, and the timestamp position using the
`--offset` option.

## Examples

Read data from exanic0:0, decode timestamps (using automatic timestamp format
detection), and dump to stdout:

```text
$ timestamp-decoder --read exanic0:0
```

Read data from a pcap file, decode timestamps (using automatic timestamp format
detection), and write to a pcap file:

```text
$ timestamp-decoder --read raw.pcap --write decode.pcap
```

Configure interface `eth2` to receive frames with a bad FCS, receive 60s
worth of data (mirror timestamp modes `fcs` or `fcs-compat`), then decode & write
out (note not all interfaces will support this ethtool option):

```text
$ sudo ethtool -K eth2 rx-fcs on
$ sudo ethtool -K eth2 rx-all on
$ sudo timeout 60 tcpdump -i eth2 -w raw.pcap
$ timestamp-decoder --read raw.pcap --write decode.pcap --32-bit --offset 4
```

Read data from a pcap file, decode ExaLINK Fusion HPT timestamps, and write
timestamps (formatted as seconds since epoch) and metadata to stdout:

```text
$ timestamp-decoder --read raw.pcap --trailer --no-payload --date '%s'
```

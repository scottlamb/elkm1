# [Elk M1](https://www.elkproducts.com/m1-security-automation-controls/) Security and Automation Controller System, in Rust

Connects to an Elk M1, currently over TCP/IP to a M1XEP. Serial port support
can also be added.

Work in progress. The `elkm1` library crate has three layers:

1. framing of packets in [Elk M1 RS232 ASCII protocol](https://www.elkproducts.com/elkdoc/m1-rs232-ascii-protocol/) and
   the undocumented Elk remote programming protocol. (done)
2. parsing of packets into higher-level messages. (WIP)
3. maintaining a view of the Elk's state based on those messages. (WIP)

The `elkm1-cli` binary crate is a quick'n'dirty CLI application to try it out.

The `elkm1-mqtt` binary crate is a daemon that bridges Elk and MQTT. Although
I'm not planning this now, in theory it could even replace an M1XEP by
multiplexing a serial port to TCP/IP connections and sending messages to a
central station.

## License

Your choice of MIT or Apache; see [LICENSE-MIT.txt](LICENSE-MIT.txt) or
[LICENSE-APACHE](LICENSE-APACHE.txt), respectively.

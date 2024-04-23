# collector

The Skupper Collector works as an add-on to a skupper site. Using Skupper's data
plane, the collector is able to infer the topology of the network and observe
traffic patterns within the network.

The collector exposes an API and metrics containing this information, and optionally embeds the
[skupper console](https://github.com/skupperproject/skupper-console) web UI.

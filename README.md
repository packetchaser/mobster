
## THIS PROJECT IS NO LONGER ACTIVE

![Mobster](http://static1.squarespace.com/static/56473ab6e4b0b678b28ed199/t/564765bbe4b06b7d18ce3137/1447519676004/mobster-banner.png)

This is an experimental project that was demonstrated at the 2015 Suricata User Conference.
It is an event stream processing engine designed to analyze Suricata EVE records like dns,
http, tls, flow, fileinfo, etc, in real-time.  The project was motivated by a need to correlate
and detect chain-of-events as meaningful patterns for behavior; otherwise known as behavioral
indicators.  It is designed to be simple requiring minimal resources. More specifically,
the primary target hardware platform for the engine is the Raspberry Pi 2 Model B.

To demonstrate the capabilities of the processing engine, the example scripts are 
implemented and patterned after the various [Bro analysis frameworks](https://www.bro.org/sphinx/frameworks/).
Please note that the example event handling scripts should not be construed to be equivalent
to the corresponding Bro scripts by any means.  The intent is to demonstrate the utility
of the event stream processing engine.

Please refer to the [Mobster Project Page](http://packetchaser.org/mobster) for additonal documentation.

---

The name, Mobster, is derived from the definition of [a group of suricatas](https://en.wikipedia.org/wiki/Meerkat), 
which is called a "mob".

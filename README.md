Multipath Dissemination Daemon
=============
The Multipath Dissemination Daemon aims to address some of the key challenges in todays network configuration, specifically the limited support for multi-homed hosts and networks.

Taking a host-centric approach, the MPDD pushes knowledge of any Internet connection to all other hosts in the network, configuring the routing tables and rules accordingly.

This host-centric approach easily augments technologies such as MPTCP, enabling resource pooling, no matter where the Internet connection actually resides. Alternatively, load balancing or other IP rules could be used
to distribute different flows over different links.

This software, while functional, is currently a prototype, so it may not always work as expected. It has only been tested in Debian 7, Ubuntu 14.04 and NS3-DCE.

Requirements
-------

libnl-3-route-dev
libmnl-dev
libconfig

Installation
-----------

    make
    make install

For an NS3-DCE compatible binary

    make ARCH=sim
    cp bin/sim/mpdd $NS3_FOLDER/build_dir/bin_dce/

Usage
-----

Permissions are required to alter network configuration.

    sudo mpdd -c /etc/mpd/mpdd.conf
    sudo mpdd -C /etc/mpd/mpdd_simple.conf

See [Example configuration](example/mpdd.conf)

The simple config is currently recommended for use with NS3.

NB.
When load balancing is enabled, route metric 0 in RT_TABLE_MAIN should not be allocated in the network manager. 

Contributing
------------

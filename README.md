wireshark-xia
=============

This README will describe how to use the files included in this repository to build a Wireshark application that supports eXpressive Internet Protocol (XIP) and Neighborhood Watch Protocol (NWP) packet dissection within the eXpressive Internet Architecture (XIA).

This how-to closely follows the Wireshark developers' guide, available here: http://www.wireshark.org/docs/wsdg_html_chunked/

In order to build from scratch, the Wireshark sources need to be obtained. One way to do this is to use the command-line Subversion client as follows:

	$ svn checkout http://anonsvn.wireshark.org/wireshark/trunk wireshark

This source can be updated by issuing the following from within the Wireshark source directory:

	$ svn update

To customize this version of Wireshark for XIA, the Wireshark-XIA sources now need to be obtained. This can be done by issuing:

	$ git clone http://github.com/cjdoucette/wireshark-xia.git

The next few steps assume that the working directory is the top-level Wireshark source directory.

Next, the Wireshark-XIA files must be added to the Wireshark source. Copy the cloned Wireshark-XIA files (excluding the compressed archive file) into the epan/dissectors/ directory within the Wireshark source. 

Three other files need to be updated to inform the compiler that we are adding dissectors. First, within the epan/dissectors/ directory, locate the file "Makefile.common" and edit it to include the following:

* Insert entries for packet-nwp.c, packet-xip.c, and packet-xip-dag.c under the heading "DISSECTOR_SRC."
* Insert entries for packet-xip-dag.h, packet-xip-dag-userland.h, packet-xip-xia.h, and packet-xip-xia-fib.h under the heading "DISSECTOR_INCLUDES."

Secondly, edit the file "CMakeLists.txt" within the epan/ directory to include the following:

* Insert entries for packet-nwp.c, packet-xip.c, and packet-xip-dag.c under the heading "DISSECTOR_SRC."

Thirdly, edit the file "etypes.h" within the epan/ directory to include the following:

* Insert entries for the XIP and NWP Ethertypes. The file is ordered numerically by the two-byte Ethertype, and each entry should be wrapped in the preprocessing directive "#ifndef". The Ethertypes for XIP and NWP are 0xC0DE and 0xC0DF, respectively.

Finally, edit the file "packet-ethertype.c" within the epan/dissectors/ directory to include the following:

* Insert entries for the XIP and NWP Ethertypes in the etype_vals array.

Once these steps have been taken, the source code can be configured and compiled with the following steps:

	$ ./autogen.sh
	$ ./configure
	$ sudo make install

Once the application has been built, it can be started from the command-line:

	$ wireshark

The examples directory contains example XIP and NWP packet captures. The samples directory contains samples of the files epan/CMakeLists.txt, epan/etypes.h, epan/dissectors/Makefile.common, and epan/dissectors/packet-ethertype.c.

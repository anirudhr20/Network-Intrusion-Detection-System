package hey;
import java.util.ArrayList;
import java.util.List;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Udp;
public class PCap {
	public static void main(String[] args) {
		List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs
		StringBuilder errbuf = new StringBuilder(); // For any error msgs
		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r != Pcap.OK || alldevs.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s",
					errbuf.toString());
			return;
		}
		System.out.println("Network devices found:");
		int i = 0;
		for (PcapIf device : alldevs) {
			String description = (device.getDescription() != null) ? device
					.getDescription() : "No description available";
			System.out.printf("#%d: %s [%s]\n", i++, device.getName(),
					description);
		}
		PcapIf device = alldevs.get(1); // Get first device in list
		System.out.printf("\nChoosing '%s' on your behalf:\n",
				(device.getDescription() != null) ? device.getDescription()
						: device.getName());
		int snaplen = 64 * 1024; // Capture all packets, no trucation
		int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
		int timeout = 10*10000 ; // 10 seconds in millis
		Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
		System.out.println(pcap);
		if (pcap == null) {
			System.err.printf("Error while opening device for capture: "
					+ errbuf.toString());
			return;
		}
		PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
			public void nextPacket(PcapPacket packet, String user) {
				System.out.println("Checking");
				byte[] data = packet.getByteArray(0, packet.size()); // the package data
				byte[] sIP = new byte[4];
				byte[] dIP = new byte[4];
				
				
				Ip4 ip = new Ip4();
//				Tcp tcp = new Tcp();
				Udp udp = new Udp();
				if (packet.hasHeader(udp)) {
					System.out.println("UDP");
				}
				
				if (packet.hasHeader(ip) == false) {
					System.out.println("Here is the problem");
					return; // Not IP packet
				}
				sIP = packet.getHeader(ip).source();
				dIP = packet.getHeader(ip).destination();
				
				/* Use jNetPcap format utilities */
				String sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
				String destinationIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP);
				
				System.out.println(data);
				System.out.println("srcIP=" + sourceIP + 
						" dstIP=" + destinationIP + 
						" caplen=" + packet.getCaptureHeader().caplen()+
						" WireLength="+ packet.getCaptureHeader().wirelen()
						);
			}
		};
		// capture first 10 packages
		pcap.loop(10, jpacketHandler, "jNetPcap");
		pcap.close();
	}
}
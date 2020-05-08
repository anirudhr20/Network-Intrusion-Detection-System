package hey;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import javax.swing.*;
import java.util.ArrayList;
import java.util.List;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;


public class Main {
	
	public static void main(String args[])
	{
		List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs
		int numIter = 100;                             // Number of Iterations to check for packets
		String[][] mainList = new String[numIter][6]; // It has the data of the table to be generated
		StringBuilder errbuf = new StringBuilder();   // For any error messages
		
		int r = Pcap.findAllDevs(alldevs, errbuf);    // This checks for the devices connected to the system (Wireless or wired)
		
		if (r != Pcap.OK || alldevs.isEmpty()) {
			System.err.printf("Can't read list of devices, error is %s",
					errbuf.toString());
			return;
		}
		
		// List all the Devices found
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
		int timeout = 10*10000 ; // 10 seconds in milli seconds
		
		Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf); // Open the device for packet capturing
		System.out.println(pcap);
		
		if (pcap == null) {
			System.err.printf("Error while opening device for capture: "
					+ errbuf.toString());
			return;
		}
		
		ArrayList<String> source = new ArrayList<String>(); // List of Source Ip address 
		ArrayList<String> dest = new ArrayList<String>();  // List of Destination Ip address 
		ArrayList<String> capLen = new ArrayList<String>(); // List of length of packet
		ArrayList<String> wireLen = new ArrayList<String>(); // List of length of data 
		ArrayList<String> type = new ArrayList<String>();  // List of types of packets recieved
		
		// Packet handling 
		PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
			public void nextPacket(PcapPacket packet, String user) {
				System.out.println("Checking");
				byte[] data = packet.getByteArray(0, packet.size()); // the package data
				byte[] sIP = new byte[4];  // store data for source ip address
				byte[] dIP = new byte[4];  // store data for destination ip address
				
				String tp = ""; 
				Ip4 ip = new Ip4();
				Tcp tcp = new Tcp();
				Udp udp = new Udp();
				
				// Check for the type of packet
				if (packet.hasHeader(udp)) {
					tp = "UDP";
				}
				if (packet.hasHeader(tcp)) {
					tp = "TCP";
				}
				if (packet.hasHeader(ip) == false) {
					System.out.println("Here is the problem");
					return; // Not IP packet
				}
				
				sIP = packet.getHeader(ip).source(); 
				dIP = packet.getHeader(ip).destination();
				
				// Using jnetpcap utilities 
				String sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
				String destinationIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP);
				String cap = Integer.toString(packet.getCaptureHeader().caplen());
				String wire = Integer.toString(packet.getCaptureHeader().wirelen());
				
				source.add(sourceIP);
				dest.add(destinationIP);
				capLen.add(cap);
				wireLen.add(wire);
				type.add(tp);
				
				System.out.println(data);
				System.out.println("srcIP=" + sourceIP + 
						" dstIP=" + destinationIP + 
						" caplen=" + packet.getCaptureHeader().caplen()+
						" WireLength="+ packet.getCaptureHeader().wirelen()
						);
			}
		};
		
		// capture first 100 packages
		pcap.loop(numIter, jpacketHandler, "jNetPcap");
		pcap.close();// close the device after capturing packets
		
		
		for(int i1=0;i1<mainList.length;i1++) {
			for(int j=0;j<mainList[i1].length;j++) {
				if(j==0) {
					mainList[i1][j] = Integer.toString(i1+1);
				}
				else if(j==1) {
					mainList[i1][j] = source.get(i1);
				}else if(j==2) {
					mainList[i1][j] = dest.get(i1);
				}else if(j==3) {
					mainList[i1][j] = capLen.get(i1);
				}else if(j==4) {
					mainList[i1][j] = wireLen.get(i1);
				}else {
					mainList[i1][j] = type.get(i1);
				}
			}
		}
		
		
		JFrame jf=new JFrame(); // Create Jframe for the GUI
		jf.setSize(1000,1000);
		
		JPanel jp=new JPanel(); // Panel for checking file
		JPanel jpack = new JPanel(); // Panel for checking the device
		JPanel jtab = new JPanel();  // Panel for jtable
		
		jf.setLayout(new FlowLayout());
		
		JLabel label1= new JLabel("File Name");
		JTextField t1= new JTextField(20);
		
		JButton b1=new JButton("Check Virus");
		JTextField result=new JTextField(20);
		
		JButton b2=new JButton("File Details");
		JTextField desc=new JTextField(20);
		
		JLabel Packet = new JLabel("Device Details");
		JTextArea net = new JTextArea(3,30);
		JButton b3 = new JButton("Get Device Details");
		
		String columns[] = {"No.","Source IP","Destination IP","Cap Length","Wire Length","Packet Type"}; //columns of the table
		
		JTable j = new JTable(mainList,columns);
		j.getColumnModel().getColumn(1).setPreferredWidth(100);
		j.getColumnModel().getColumn(2).setPreferredWidth(100);
		j.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
		
		
		WindowListener listener = new WindowAdapter() {
			public void windowClosing(WindowEvent winEvt) {
				System.exit(0);
			}
		};
		
		jp.add(label1);
		jp.add(t1);
		
		jp.add(b1);
		jp.add(result);
		
		jp.add(b2);
		jp.add(desc);
		
		jpack.add(Packet);
		jpack.add(net);
		jpack.add(b3);
		
		jtab.add(new JScrollPane(j)); // Add scrolling option to table
		
		jf.add(jp);
		jf.add(jpack);
		jf.add(jtab);
		jf.addWindowListener(listener);
		
		jf.setVisible(true);
		
		//checking for virus statstcally
		CheckVirus checkvirus=new CheckVirus();
		b1.addActionListener(new ActionListener() {
			
			public void actionPerformed(ActionEvent e)
			{
				
				checkvirus.filename=t1.getText();
				checkvirus.compute(); //decide if virus is present
				checkvirus.addToLog();// add virus details to decided file
				if(checkvirus.found)
				{
					result.setText("Virus found");
					
				}
					
				else
				{
					result.setText("No virus in the file");
					
				}
					
				
				try {
					
					
				} catch(Exception e1){
					e1.printStackTrace();
					
				}
				
			}
		});
		
		
		b2.addActionListener(new ActionListener() {
			
			public void actionPerformed(ActionEvent e)
			{
				
				
				if(checkvirus.found)
				{
					
					desc.setText("File is infected with "+checkvirus.virus+" virus");
				}
					
				else
				{
					
					desc.setText("File safe to use");
				}
					
				
				try {
					
					
				} catch(Exception e1){
					e1.printStackTrace();
					
				}
				
				
				
				
				
			}
		});
		
		// Get device name of the device connected
		b3.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				net.setText(device.getName()+" "+device.getDescription());
			}
		});
		
	}
}
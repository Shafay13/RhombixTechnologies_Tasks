from scapy.all import sniff, wrpcap, rdpcap
import os

# Define Desktop path
desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")

# Set output file names
pcap_file = os.path.join(desktop_path, "captured_packets.pcap")
txt_file = os.path.join(desktop_path, "captured_packets.txt")

# Packet storage
packets = []

# Process each captured packet
def packet_handler(packet):
    print(packet.summary())
    packets.append(packet)

# Start sniffing (20 packets only)
print("Sniffing 20 IP packets...")
sniff(prn=packet_handler, filter="ip", count=20)

# Save to PCAP
if packets:
    wrpcap(pcap_file, packets)
    print(f"\n✅ PCAP saved to: {pcap_file}")

    # Read and convert to TXT
    read_packets = rdpcap(pcap_file)
    with open(txt_file, "w") as f:
        for i, pkt in enumerate(read_packets, 1):
            f.write(f"Packet {i}:\n")
            f.write(pkt.summary() + "\n")
            f.write(str(pkt.show(dump=True)))
            f.write("\n" + "-"*60 + "\n")

    print(f"✅ Text summary saved to: {txt_file}")
else:
    print("❌ No packets captured.")

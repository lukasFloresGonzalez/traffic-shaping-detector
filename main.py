import numpy as np
from scapy.all import PcapNgReader
import argparse


def process_packet_data(packet, timestamp_dict, size_dict):
    ts = int(packet.time)
    size_dict[ts] = size_dict.get(ts, 0) + len(packet)
    timestamp_dict[ts] = timestamp_dict.get(ts, 0) + 1


def read_pcapng(file_path):
    timestamp_dict = {}
    size_dict = {}

    try:
        with PcapNgReader(file_path) as pcap_reader:
            for packet in pcap_reader:
                process_packet_data(packet, timestamp_dict, size_dict)

    except Exception as e:
        print(f"Error reading pcapng file: {e}")

    return timestamp_dict, size_dict


def analyze_traffic_shaping(file_path):
    timestamp_dict, size_dict = read_pcapng(file_path)
    packet_numbers, byte_sizes = list(timestamp_dict.values()), list(size_dict.values())
    threshold = 3 * np.mean(np.float32(byte_sizes) / np.float32(packet_numbers))

    if np.std(byte_sizes) < threshold:
        print("Traffic Shaping detectado!")
    else:
        print("NO Traffic Shaping!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check for Traffic Shaping in a pcapng file.")
    parser.add_argument("file_path", type=str, help="Path to the pcapng file")
    args = parser.parse_args()

    analyze_traffic_shaping(args.file_path)

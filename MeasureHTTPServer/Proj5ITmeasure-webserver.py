from scapy.all import *
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.inet import IP, TCP
import sys
import math
import numpy as np  # Added for more robust mathematical operations

def percentile(data, percentile):
    if not data:
        return 0
    sorted_data = sorted(data)
    index = percentile * (len(sorted_data) - 1)
    floor_index = int(index)
    ceil_index = min(floor_index + 1, len(sorted_data) - 1)
    if floor_index == ceil_index:
        return sorted_data[floor_index]
    else:
        lower = sorted_data[floor_index]
        upper = sorted_data[ceil_index]
        new_value = (index - floor_index) * (upper - lower)
        return lower + new_value

def find_divergence(measured_distribution, modeled_distribution, epsilon=1e-10):
    if len(measured_distribution) != len(modeled_distribution):
        raise ValueError("Input arrays not equal in size.")

    kl_sum = 0.0
    for i in range(len(measured_distribution)):
        m = max(measured_distribution[i], epsilon)
        mo = max(modeled_distribution[i], epsilon)
        kl_sum += m * math.log2(m / mo)

    return kl_sum

def exponential_distribution(data, mean_response_time):
    if not data or mean_response_time <= 0:
        return [], []

    rate = 1 / mean_response_time
    num_buckets = 10
    max_latency = max(data)
    bucket_size = max_latency / num_buckets
    bucket_ranges = [i * bucket_size for i in range(num_buckets + 1)]

    measured_distribution = [0] * num_buckets

    for latency in data:
        bucket_index = min(int(latency / bucket_size), num_buckets - 1)
        measured_distribution[bucket_index] += 1

    total_observations = len(data)
    normalized_measured_distribution = [count / total_observations for count in measured_distribution]

    modeled_distribution = []
    for i in range(1, num_buckets + 1):
        modeled_count = (1 - math.exp(-rate * bucket_ranges[i])) - (1 - math.exp(-rate * bucket_ranges[i-1]))
        modeled_distribution.append(modeled_count)

    sum_modeled_distribution = sum(modeled_distribution)
    normalized_modeled_distribution = [count / sum_modeled_distribution for count in modeled_distribution]

    return normalized_modeled_distribution, normalized_measured_distribution

def measure(pcap, server_ip, server_port):
    load_layer("http")
    packets = rdpcap(pcap)
    request_times = {}
    latencies = []

    for packet in packets:
        if packet.haslayer(IP) and packet.haslayer(TCP):
            src_ip = packet[IP].src
            dest_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dest_port = packet[TCP].dport

            if packet.haslayer(HTTP) and HTTPRequest in packet:
                if dest_ip == server_ip and dest_port == int(server_port):
                    request_times[(src_ip, src_port, dest_ip, dest_port)] = packet.time
            elif packet.haslayer(HTTP) and HTTPResponse in packet:
                if src_ip == server_ip and src_port == int(server_port):
                    request_key = (dest_ip, dest_port, src_ip, src_port)
                    if request_key in request_times:
                        latency = packet.time - request_times[request_key]
                        latencies.append(latency)
                        del request_times[request_key]

    latencies = [float(latency) for latency in latencies]  # Ensure latencies are in float
    if latencies:
        avg_latency = sum(latencies) / len(latencies)
        print(f"AVERAGE LATENCY: {avg_latency:.5f}")
    else:
        avg_latency = 0

    percentiles = [percentile(latencies, p) for p in [0.25, 0.50, 0.75, 0.95, 0.99]]
    print(f"PERCENTILES: {' '.join([f'{p:.5f}' for p in percentiles])}")

    modeled_distribution, measured_distribution = exponential_distribution(latencies, avg_latency)
    kl_divergence = find_divergence(measured_distribution, modeled_distribution)
    print(f"KL DIVERGENCE: {kl_divergence:.5f}")


def main():
    if len(sys.argv) != 4:
        print("Usage: measure-webserver.py <input-file> <server-ip> <server-port>")
        sys.exit(1)

    pcap_filename = sys.argv[1]
    server_ip = sys.argv[2]
    server_port = int(sys.argv[3])

    measure(pcap_filename, server_ip, server_port)


if __name__ == "__main__":
    main()


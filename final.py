import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from scipy.ndimage import median_filter

csv = 'Captures\capture9.csv'

# Read the CSV file and create a DataFrame
df = pd.read_csv(csv)

# Convert the "Time" column to a datetime object
date_format = "%H:%M:%S.%f"
df['Time'] = pd.to_datetime(df['Time'], format=date_format)

# Group by one-second intervals and count the occurrences
grouped = df.groupby(pd.Grouper(key='Time', freq='1S')).size().reset_index(name='count')

# Extract the seconds (time) and packet counts (count) for the scatter plot
seconds = grouped['Time']
packet_counts = grouped['count']

# Find the rolling median for a 10 second window
rolling_median = median_filter(packet_counts, size=10)

# Calculate the dynamic threshold based on rolling_median
mean = np.mean(rolling_median)
std_dev = np.std(rolling_median)
threshold = mean + 1 * std_dev
print(threshold)

outliers = [x if x > threshold else 0 for x in list(packet_counts)]

attack_points = []

for i in range(len(outliers)):
    if i - 3 >= 0 and i + 3 < len(outliers):
        if outliers[i - 5:i].count(0) > 4 and outliers[i + 1:i + 6].count(0) > 4:
            attack_points.append(0)
        else:
            attack_points.append(outliers[i])
    else:
        attack_points.append(outliers[i])

attack_points[0] = 0
attack_points[-1]= 0

# Create a scatter plot
plt.figure(figsize=(10, 6))  # Adjust the figure size if needed
plt.scatter(seconds, packet_counts, s=10, marker='o', label='Packets per Second', alpha=0.8)
plt.plot(seconds, packet_counts, label='Packet Counts')

# Find the targeted MACs in case of attack detection
def detect_targets(file):
    import csv
    from collections import Counter

    # Initialize counters for source and destination MAC addresses
    source_counter = Counter()
    destination_counter = Counter()
    associated_destination = {}

    # Read the CSV file
    with open(file, 'r') as csv_file:
        csv_reader = csv.DictReader(csv_file)

        # Iterate through each row in the CSV
        for row in csv_reader:
            source_mac = row['Source']
            destination_mac = row['Destination']

            # Update the counters for source and destination MAC addresses
            source_counter[source_mac] += 1
            destination_counter[destination_mac] += 1

            # Track the associations between source and destination MAC addresses
            if source_mac not in associated_destination:
                associated_destination[source_mac] = []
            associated_destination[source_mac].append(destination_mac)

    # Find the most common source MAC address
    most_common_source_mac, source_count = source_counter.most_common(1)[0]

    # Find the associated destination MAC addresses for the most common source MAC address
    associated_destinations = associated_destination[most_common_source_mac]

    # Find the most common destination MAC address among associated destinations
    most_common_destination_mac, destination_count = Counter(associated_destinations).most_common(1)[0]

    print(f"Main targeted MAC Address: {most_common_source_mac} (targeted {source_count} times)")
    print(f"Main targeted MAC Address associated with {most_common_source_mac}: {most_common_destination_mac} (targeted {destination_count} times)")

if threshold >= 1:
    # Create a scatter plot with seconds on the x-axis and result on the y-axis
    plt.axhline(y=threshold, color='red', linestyle='--', label='Dynamic Threshold')
    seconds_x = [seconds[i] for i in range(len(attack_points)) if attack_points[i] > 0]
    result_y = [attack_points[i] for i in range(len(attack_points)) if attack_points[i] > 0]
    plt.scatter(seconds_x, result_y,  c='red', s=30, marker='x', label='Malicious Traffic')
    result = "Attack Detected"
    label = "Status:"
    plt.text(seconds.iloc[0], max(packet_counts), f"{label} {result}", verticalalignment='top', horizontalalignment='left', color='red')
    # Find the targeted MACs
    detect_targets(csv)
else:
    result = "Normal Traffic"
    label = "Status:"
    plt.text(seconds.iloc[0], max(packet_counts), f"{label} {result}", verticalalignment='top', horizontalalignment='left', color='blue') 

plt.legend(loc='upper right')

# Add labels and title
plt.xlabel("Time (s)")
plt.ylabel("Deauth Packets / 1 sec")
plt.title("Scatter Plot of Deauthentication Packets per Second Over Time")

# Display the plot
plt.grid(True)
plt.tight_layout()
plt.show()
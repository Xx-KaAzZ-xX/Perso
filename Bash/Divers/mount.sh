#!/bin/bash

# Usage message
usage() {
    echo "Usage: $0 -i image.img -d /mnt/image_17"
    exit 1
}

# Parse command-line arguments
while getopts ":i:d:" opt; do
  case $opt in
    i) IMAGE="$OPTARG"
    ;;
    d) MOUNT_DIR="$OPTARG"
    ;;
    \?) echo "Invalid option -$OPTARG" >&2; usage
    ;;
    :) echo "Option -$OPTARG requires an argument." >&2; usage
    ;;
  esac
done

# Check if both arguments are provided
if [ -z "$IMAGE" ] || [ -z "$MOUNT_DIR" ]; then
    usage
fi

# Check if the image file exists
if [ ! -f "$IMAGE" ]; then
    echo "Error: Image file $IMAGE does not exist."
    exit 1
fi

# Get partition info using fdisk, skipping the header lines
PARTITION_INFO=$(fdisk -l "$IMAGE" | awk '/^Device/ {found=1; next} found {print}' | nl -v 1)

# Check if there are any partitions
if [ -z "$PARTITION_INFO" ]; then
    echo "Error: No valid partitions found in the image."
    exit 1
fi

# Display partitions and let the user select one
echo "Available partitions in $IMAGE:"
echo "$PARTITION_INFO"

echo
read -p "Enter the number of the partition to mount: " PART_NUM

# Validate the user's choice
TOTAL_PARTITIONS=$(echo "$PARTITION_INFO" | wc -l)
if [ "$PART_NUM" -lt 1 ] || [ "$PART_NUM" -gt "$TOTAL_PARTITIONS" ]; then
    echo "Invalid partition number. Exiting."
    exit 1
fi

# Extract the chosen partition info
CHOSEN_PARTITION=$(echo "$PARTITION_INFO" | sed -n "${PART_NUM}p")

# Adjust the partition start offset, depending on whether there was a boot flag
if echo "$CHOSEN_PARTITION" | grep -q "*"; then
    OFFSET=$(echo "$CHOSEN_PARTITION" | awk '{print $4}')  # Adjust for boot flag
    echo "begin offset of $CHOSEN_PARTITION is $OFFSET"
else
    #OFFSET=$(echo "$CHOSEN_PARTITION" | awk '{print $2}')  # No boot flag
    OFFSET=$(echo "$CHOSEN_PARTITION" | awk '{print $3}')
fi

# Calculate the byte offset (512 bytes per sector)
BYTE_OFFSET=$((512 * OFFSET))

# Create the mount point directory if it doesn't exist
mkdir -p "$MOUNT_DIR"

# Mount the image
mount -o ro,norecovery,offset=$((512 * ${OFFSET})) "$IMAGE" "$MOUNT_DIR"

# Check if the mount was successful
if [ $? -eq 0 ]; then
    echo "Image mounted successfully at $MOUNT_DIR with offset $BYTE_OFFSET."
else
    echo "Error: Failed to mount the image."
    exit 1
fi

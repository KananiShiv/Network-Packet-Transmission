#include "hw1.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

void print_packet_sf(unsigned char packet[])
{

    unsigned int srcAddrByte1 = packet[0];
    unsigned int srcAddrByte2 = packet[1];
    unsigned int srcAddrByte3 = packet[2];
    unsigned int srcAddrByte4 = packet[3];
    unsigned int sourceAddress = (srcAddrByte1 << 20) | (srcAddrByte2 << 12) | (srcAddrByte3 << 4) | (srcAddrByte4 >> 4);

    unsigned int destAddrByte1 = srcAddrByte4 & 0x0F;
    unsigned int destAddrByte2 = packet[4];
    unsigned int destAddrByte3 = packet[5];
    unsigned int destAddrByte4 = packet[6];
    unsigned int destinationAddress = (destAddrByte1 << 24) | (destAddrByte2 << 16) | (destAddrByte3 << 8) | destAddrByte4;

    unsigned int srcPortByte = packet[7];
    unsigned int sourcePort = srcPortByte >> 4;

    unsigned int destPortByte = srcPortByte & 0x0F;
    unsigned int destinationPort = destPortByte;

    unsigned int fragOffsetByte1 = packet[8];
    unsigned int fragOffsetByte2 = packet[9];
    unsigned int fragmentOffset = (fragOffsetByte1 << 6) | (fragOffsetByte2 >> 2);

    unsigned int packetLengthByte1 = fragOffsetByte2 & 0x03;
    unsigned int packetLengthByte2 = packet[10];
    unsigned int packetLengthByte3 = packet[11];
    unsigned int packetLength = (packetLengthByte1 << 12) | (packetLengthByte2 << 4) | (packetLengthByte3 >> 4);

    unsigned int maxHopCountByte1 = packetLengthByte3 & 0xF;
    unsigned int maxHopCountByte2 = packet[12];
    unsigned int maxHopCount = (maxHopCountByte1 << 1) | ((maxHopCountByte2 >> 7) & 0x1);

    unsigned int checksumByte1 = maxHopCountByte2 & 0x7F;
    unsigned int checksumByte2 = packet[13];
    unsigned int checksumByte3 = packet[14];
    unsigned int checksum = (checksumByte1 << 16) | (checksumByte2 << 8) | checksumByte3;

    unsigned int compressionSchemeByte = packet[15];
    unsigned int compressionScheme = (compressionSchemeByte >> 6) & 0x03;

    unsigned int trafficClass = compressionSchemeByte & 0x3F;

    printf("Source Address: %u\n", sourceAddress);
    printf("Destination Address: %u\n", destinationAddress);
    printf("Source Port: %u\n", sourcePort);
    printf("Destination Port: %u\n", destinationPort);
    printf("Fragment Offset: %u\n", fragmentOffset);
    printf("Packet Length: %u\n", packetLength);
    printf("Maximum Hop Count: %u\n", maxHopCount);
    printf("Checksum: %u\n", checksum);
    printf("Compression Scheme: %u\n", compressionScheme);
    printf("Traffic Class: %u\n", trafficClass);

    printf("Payload: ");
    unsigned payloadIndex = 16;
    while (payloadIndex < packetLength)
    {
        int32_t value = (packet[payloadIndex] << 24) | (packet[payloadIndex + 1] << 16) | (packet[payloadIndex + 2] << 8) | packet[payloadIndex + 3];
        payloadIndex += 4;

        if (payloadIndex < packetLength)
        {
            printf("%d ", value);
        }
        else
        {
            printf("%d", value);
        }
    }
    printf("\n");
}

unsigned int compute_checksum_sf(unsigned char packet[])
{
    unsigned int sum = 0;

    unsigned int packetLenByte1 = packet[9] & 0x03;
    unsigned int packetLenByte2 = packet[10];
    unsigned int packetLenByte3 = packet[11];
    unsigned int packetLength1 = (packetLenByte1 << 12) | (packetLenByte2 << 4) | (packetLenByte3 >> 4);
    unsigned int payloadLength = packetLength1 - 16;
    unsigned int payloadStart = 16;
    unsigned int srcAddrByte1 = packet[0];
    unsigned int srcAddrByte2 = packet[1];
    unsigned int srcAddrByte3 = packet[2];
    unsigned int srcAddrByte4 = packet[3];
    unsigned int sourceAddress = (srcAddrByte1 << 20) | (srcAddrByte2 << 12) | (srcAddrByte3 << 4) | (srcAddrByte4 >> 4);
    unsigned int destAddrByte1 = srcAddrByte4 & 0x0F;
    unsigned int destAddrByte2 = packet[4];
    unsigned int destAddrByte3 = packet[5];
    unsigned int destAddrByte4 = packet[6];
    unsigned int destinationAddress = (destAddrByte1 << 24) | (destAddrByte2 << 16) | (destAddrByte3 << 8) | destAddrByte4;
    unsigned int srcPortByte = packet[7];
    unsigned int sourcePort = srcPortByte >> 4;
    unsigned int destPortByte = srcPortByte & 0x0F;
    unsigned int destinationPort = destPortByte;
    unsigned int fragOffsetByte1 = packet[8];
    unsigned int fragOffsetByte2 = packet[9];
    unsigned int fragmentOffset = (fragOffsetByte1 << 6) | (fragOffsetByte2 >> 2);
    unsigned int packetLength2 = (packetLenByte1 << 12) | (packetLenByte2 << 4) | (packetLenByte3 >> 4);
    unsigned int maxHopCountByte1 = packet[11] & 0xF;
    unsigned int maxHopCountByte2 = packet[12];
    unsigned int maxHopCount = (maxHopCountByte1 << 1) | ((maxHopCountByte2 >> 7) & 0x1);
    unsigned int compressionSchemeByte = packet[15];
    unsigned int compressionScheme = (compressionSchemeByte >> 6) & 0x03;
    unsigned int trafficClass = compressionSchemeByte & 0x3F;

    sum = sourceAddress + destinationAddress + sourcePort + destinationPort + fragmentOffset + packetLength2 + maxHopCount + compressionScheme + trafficClass;

    for (unsigned int i = payloadStart; i < payloadLength + payloadStart; i += 4)
    {
        int value = (packet[i] << 24) | (packet[i + 1] << 16) | (packet[i + 2] << 8) | packet[i + 3];
        sum += abs(value);
    }

    unsigned int checksum = ((sum) % ((1 << 23) - 1));
    return checksum;
}

unsigned int reconstruct_array_sf(unsigned char *packets[], unsigned int packets_len, int *array, unsigned int array_len)
{
    unsigned int count = 0;
    unsigned int packetsArraySize = packets_len * sizeof(unsigned int);
    unsigned int *goodPacketIndexes = (unsigned int *)malloc(packetsArraySize);
    unsigned int packetsCount = 0;

    for (unsigned int i = 0; i < packets_len; i++)
    {
        unsigned char *packet = packets[i];
        unsigned int checksum = compute_checksum_sf(packet);
        unsigned int packetChecksumHigh = (packet[12] & 0x7F) << 16;
        unsigned int packetChecksumMid = packet[13] << 8;
        unsigned int packetChecksumLow = packet[14];
        unsigned int packetChecksum = packetChecksumHigh | packetChecksumMid | packetChecksumLow;

        if (checksum == packetChecksum)
        {
            goodPacketIndexes[packetsCount++] = i;
        }
    }
    // printf("Computed Checksum: %u, Packet Checksum: %u\n", checksum, packetChecksum);

    for (unsigned int i = 0; i < packetsCount; i++)
    {
        unsigned char *packet = packets[goodPacketIndexes[i]];
        unsigned int fragmentOffsetHigh = packet[8] << 6;
        unsigned int fragmentOffsetLow = packet[9] >> 2;
        unsigned int fragmentOffset = fragmentOffsetHigh | fragmentOffsetLow;
        unsigned int index = fragmentOffset / sizeof(int);

        unsigned int packetLengthHigh = (packet[9] & 0x03) << 12;
        unsigned int packetLengthMid = packet[10] << 4;
        unsigned int packetLengthLow = packet[11] >> 4;
        unsigned int packetLength = packetLengthHigh | packetLengthMid | packetLengthLow;
        // printf("Fragment Offset: %u, Index: %u\n", fragmentOffset, index);

        for (unsigned int payloadIndex = 16; payloadIndex < packetLength; payloadIndex += 4)
        {
            if (index < array_len)
            {
                int valueHigh = packet[payloadIndex] << 24;
                int valueMidHigh = packet[payloadIndex + 1] << 16;
                int valueMidLow = packet[payloadIndex + 2] << 8;
                int valueLow = packet[payloadIndex + 3];
                array[index] = valueHigh | valueMidHigh | valueMidLow | valueLow;
                count++;
                // printf("Count incremented to %u\n", count);
            }
            index++;
        }
    }

    free(goodPacketIndexes);
    return count;
}

unsigned int packetize_array_sf(int *array, unsigned int array_len, unsigned char *packets[], unsigned int packets_len,
                                unsigned int max_payload, unsigned int src_addr, unsigned int dest_addr,
                                unsigned int src_port, unsigned int dest_port, unsigned int maximum_hop_count,
                                unsigned int compression_scheme, unsigned int traffic_class)
{

    bool debug = false;
    unsigned int x = 0;
    unsigned int headerSize = 16;
    unsigned int maxIntegersInPayload = max_payload / 4;

    if (debug)
    {
        printf("Starting packetization. Array length: %u, Max payload: %u\n", array_len, max_payload);
    }

    for (unsigned int i = 0; i < array_len; i += maxIntegersInPayload)
    {
        if (x >= packets_len)
        {
            if (debug)
            {
                printf("Packet limit reached. Stopping packetization.\n");
            }
            break;
        }

        unsigned int integersInCurrentPacket;
        if (i + maxIntegersInPayload > array_len)
        {
            integersInCurrentPacket = array_len - i;
        }
        else
        {
            integersInCurrentPacket = maxIntegersInPayload;
        }

        unsigned int payloadSize = integersInCurrentPacket * 4;
        unsigned int packetLength = headerSize + payloadSize;

        if (debug)
        {
            printf("Allocating packet %u with length %u.\n", x, packetLength);
        }

        packets[x] = malloc(packetLength);

        if (packets[x] == NULL)
        {
            if (debug)
            {
                printf("Memory allocation failed for packet %u.\n", x);
            }
            break;
        }
        for (unsigned int k = 0; k < packetLength; ++k)
        {
            packets[x][k] = 0;
        }
        packets[x][0] = src_addr >> 20;
        packets[x][1] = (src_addr >> 12) & 0xFF;
        packets[x][2] = (src_addr >> 4) & 0xFF;
        packets[x][3] = ((src_addr & 0xF) << 4) | ((dest_addr >> 24) & 0xF);
        packets[x][4] = (dest_addr >> 16) & 0xFF;
        packets[x][5] = (dest_addr >> 8) & 0xFF;
        packets[x][6] = dest_addr & 0xFF;
        packets[x][7] = (src_port << 4) | (dest_port & 0xF);

        unsigned int byteOffset = i * sizeof(int);
        packets[x][8] = (byteOffset >> 8) & 0xFF;
        packets[x][9] = (packets[x][9] & 0x03) | ((byteOffset & 0x3F) << 2);
        packets[x][10] = (packetLength >> 4) & 0xFF;
        packets[x][11] = ((packetLength & 0xF) << 4) | ((maximum_hop_count >> 1) & 0xF);

        if (debug)
        {
            printf("Packet %u header set. Source: %u, Destination: %u, Source Port: %u, Destination Port: %u\n",
                   x, src_addr, dest_addr, src_port, dest_port);
        }
        for (unsigned int j = 0; j < payloadSize; j += 4)
        {
            unsigned int arrayIndex = i + (j / 4);
            int currentInt = array[arrayIndex];
            packets[x][16 + j] = (currentInt >> 24) & 0xFF;
            packets[x][17 + j] = (currentInt >> 16) & 0xFF;
            packets[x][18 + j] = (currentInt >> 8) & 0xFF;
            packets[x][19 + j] = currentInt & 0xFF;
        }
        packets[x][12] = ((maximum_hop_count & 0x1) << 7);
        packets[x][15] = (compression_scheme << 6) | (traffic_class & 0x3F);
        unsigned int checksum = compute_checksum_sf(packets[x]);
        packets[x][12] |= (checksum >> 16) & 0x7F;
        packets[x][13] = (checksum >> 8) & 0xFF;
        packets[x][14] = checksum & 0xFF;

        if (debug)
        {
            printf("Packet %u constructed. Checksum: %u\n", x, checksum);
        }

        x++;
    }
    return x;
}

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.io.*;
import java.net.Socket;
import java.security.Key;
import java.security.interfaces.RSAPublicKey;

/**
 * CryptoClient: Project 8 CS 380
 *
 * @author Cary Anderson
 * */
public class CryptoClient {

    public static void main(String[] args) {
        try {
            ObjectInputStream iIS = new ObjectInputStream(new FileInputStream("public.bin"));
            RSAPublicKey teachersPublicKey = (RSAPublicKey) iIS.readObject();

            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream oj = new ObjectOutputStream(byteArrayOutputStream);

            Cipher cipher = Cipher.getInstance("RSA");
            Key mySessionKey = KeyGenerator.getInstance("AES").generateKey(); // OUR VERY OWN SYMMETRIC AES KEY

            cipher.init(Cipher.ENCRYPT_MODE, teachersPublicKey); // Use the professor's public key to encrypt my key
            oj.writeObject(mySessionKey);

            Socket socket = new Socket("45.50.5.238", 38008);

            byte[] encipheredKey = cipher.doFinal(byteArrayOutputStream.toByteArray()); // Encrypt the session key (as bytes)
            socket.getOutputStream().write(createPacket(encipheredKey, 38008));

            readAndPrint(socket.getInputStream());

            Cipher cipher2 = Cipher.getInstance("AES");
            cipher2.init(Cipher.ENCRYPT_MODE, mySessionKey);

            for (int i = 1; i < 11; i++) {
                System.out.println("\nSending data size: " + (int) Math.pow((double)2, (double) i));
                byte[] temp = new byte[(int) Math.pow((double)2, (double) i)];
                for (int j = 0; j < temp.length; j++) {
                    temp[j] = 13;
                }
                long tempTime = System.nanoTime();
                socket.getOutputStream().write(cipher2.doFinal(createPacket(temp, 38008)));
                readAndPrint(socket.getInputStream());
                System.out.println("RTT: " + (System.nanoTime() - tempTime)/1000000 + "ms");
            }
        } catch (Exception e) {
            e.printStackTrace(); // All of these stupid functions just throw way too many types of exceptions
        }
    }

    /**
     * Send a packet with data length
     *
     * @param data The bytes to send as data
     * @param destinationPort The destination port for the UDP header
     * */
    private static byte[] createPacket(byte[] data, int destinationPort) {

        byte[] send = new byte[28];

        send[0] = (byte) ((4 << 4) + 5); // Version 4 and 5 words
        send[1] = 0; // TOS (Don't implement)
        send[2] = 0; // Total length
        send[3] = 22; // Total length
        send[4] = 0; // Identification (Don't implement)
        send[5] = 0; // Identification (Don't implement)
        send[6] = (byte) 0b01000000; // Flags and first part of Fragment offset
        send[7] = (byte) 0b00000000; // Fragment offset
        send[8] = 50; // TTL = 50
        send[9] = 0x11; // Protocol (UDP = 17)
        send[10] = 0; // CHECKSUM
        send[11] = 0; // CHECKSUM
        send[12] = (byte) 127; // 127.0.0.1 (source address)
        send[13] = (byte) 0; // 127.0.0.1 (source address)
        send[14] = (byte) 0; // 127.0.0.1 (source address)
        send[15] = (byte) 1; // 127.0.0.1 (source address)
        send[16] = (byte) 0x2d; // (destination address)
        send[17] = (byte) 0x32; // (destination address)
        send[18] = (byte) 0x5; // (destination address)
        send[19] = (byte) 0xee; // (destination address)

        short length = (short) (28 + data.length); // Quackulate the total length
        byte right = (byte) (length & 0xff);
        byte left = (byte) ((length >> 8) & 0xff);
        send[2] = left;
        send[3] = right;

        short checksum = calculateChecksum(send); // Quackulate the checksum

        byte second = (byte) (checksum & 0xff);
        byte first = (byte) ((checksum >> 8) & 0xff);
        send[10] = first;
        send[11] = second;

        /*
        * UDP Header
        * */
        short udpLen = (short) (8 + data.length);
        byte rightLen = (byte) (udpLen & 0xff);
        byte leftLen = (byte) ((udpLen >> 8) & 0xff);

        send[20] = (byte) 12; // Source Port
        send[21] = (byte) 34; // Source Port
        send[22] = (byte) ((destinationPort >> 8) & 0xff); // Destination Port
        send[23] = (byte) (destinationPort & 0xff); // Destination Port
        send[24] = leftLen; // Length
        send[25] = rightLen; // Length
        send[26] = 0; // Checksum
        send[27] = 0; // Checksum

        /*
        * pseudoheader + actual header + data to calculate checksum
        * */
        byte[] checksumArray = new byte[12 + 8]; // 12 = pseudoheader, 8 = UDP Header
        checksumArray[0] = send[12]; // Source ip address
        checksumArray[1] = send[13]; // Source ip address
        checksumArray[2] = send[14]; // Source ip address
        checksumArray[3] = send[15]; // Source ip address
        checksumArray[4] = send[16]; // Destination ip address
        checksumArray[5] = send[17]; // Destination ip address
        checksumArray[6] = send[18]; // Destination ip address
        checksumArray[7] = send[19]; // Destination ip address
        checksumArray[8] = 0; // Zeros for days
        checksumArray[9] = send[9]; // Protocol
        checksumArray[10] = send[24]; // Udp length
        checksumArray[11] = send[25]; // Udp length
        // end pseudoheader
        checksumArray[12] = send[20]; // Source Port
        checksumArray[13] = send[21]; // Source Port
        checksumArray[14] = send[22]; // Destination Port
        checksumArray[15] = send[23]; // Destination Port
        checksumArray[16] = send[24]; // Length
        checksumArray[17] = send[25]; // Length
        checksumArray[18] = send[26]; // Checksum
        checksumArray[19] = send[27]; // Checksum
        // end actual header
        checksumArray = concatenateByteArrays(checksumArray, data); // Append data

        short udpChecksum = calculateChecksum(checksumArray);
        byte rightCheck = (byte) (udpChecksum & 0xff);
        byte leftCheck = (byte) ((udpChecksum >> 8) & 0xff);

        send[26] = leftCheck; // Save checksum
        send[27] = rightCheck; // Save checksum

        send = concatenateByteArrays(send, data);

        return send;
    }

    /**
     * Given an input stream, read 4 bytes and print them
     *
     * @param is The input stream to read from
     * */
    private static void readAndPrint(InputStream is) {
        try {
            int a = is.read();
            int b = is.read();
            int c = is.read();
            int d = is.read();
            System.out.print("Received: ");
            System.out.println("0x" + Integer.toString(a, 16) + Integer.toString(b, 16) + Integer.toString(c, 16) + Integer.toString(d, 16));
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
    }

    /**
     * Concatenate one array with another
     *
     * @param first First array
     * @param second Second array
     * */
    private static byte[] concatenateByteArrays(byte[] first, byte[] second) {
        int firstLength = first.length;
        int secondLength = second.length;

        byte[] ret = new byte[first.length + second.length];
        System.arraycopy(first, 0, ret, 0, first.length);
        System.arraycopy(second, 0, ret, first.length, second.length);

        return ret;
    }

    /**
     * Calculate internet checksum
     *
     * @param array Packet to compute the checksum
     * @return The checksum
     * */
    public static short calculateChecksum(byte[] array) {
        int length = array.length;
        int i = 0;

        int sum = 0;
        int data;

        // Count down
        while (length > 1) {
            data = (((array[i] << 8) & 0xFF00) | ((array[i + 1]) & 0xFF));
            sum += data;

            if ((sum & 0xFFFF0000) > 0) {
                sum = sum & 0xFFFF;
                sum += 1;
            }

            i = i + 2;
            length = length - 2;
        }

        if (length > 0) {
            sum += (array[i] << 8 & 0xFF00);
            if ((sum & 0xFFFF0000) > 0) {
                sum = sum & 0x0000FFFF;
                sum += 1;
            }
        }

        sum = ~sum;
        sum = sum & 0xFFFF;
        return (short) sum;
    }
}

package utils;

import burp.BurpExtender;
import pcap.reconst.compression.CompressionType;
import pcap.reconst.compression.UncompressImpl;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * HttpUtils
 * Implements Ansible Playbook entry by CLI
 * <p>
 * :author:    goofts <goofts@zl.com>
 * :homepage:  https://github.com/goofts
 * :license:   LGPL, see LICENSE for more details.
 * :copyright: Copyright (c) 2019 Goofts. All rights reserved
 */
public class HttpUtils {
    private static final int MAX_HEADER_SIZE = 32 * 1024;
    private static final Pattern CONTINUE_PATTERN = Pattern.compile("(?s)HTTP\\/1\\.1 100 Continue(.*?)\\r\\n\\r\\n");

    public static byte[] stripContinueFromRequests(byte[] input) {
        byte[] result = input;

        //Loop until we fail to find any more
        while (true)
        {
            String initialPart = new String(result, 0, Math.min(MAX_HEADER_SIZE, result.length));
            Matcher m = CONTINUE_PATTERN.matcher(initialPart);

            if (m.find())
            {
                int stringIndex = m.start();
                final int stringLength = m.end() - m.start();

                result = new byte[input.length - stringLength];
                //Copy up to the string we wish to exclude
                System.arraycopy(input, 0, result, 0, stringIndex);
                //Copy the other side of the byte array after the string we wish to exclude
                System.arraycopy(input, stringIndex + stringLength, result, stringIndex, input.length - (stringIndex + stringLength));
            }
            else
            {
                //No more to find - time to return
                break;
            }
        }
        return result;
    }

    /**
     * Decompresses the body of applicable HTTP streams.
     *
     * @param input A byte array representing one side of the HTTP conversation.
     * @return The input without the body ungzipped, or the original input if
     * it's not a well formed gzip stream.
     */
    public static byte[] decompressIfRequired(byte[] input)
    {
        final int MAX_HEADER_SIZE = 16 * 1024;
        final String HEADER_BODY_SEPERATOR = "\r\n\r\n";

        String initialPart = new String(input, 0, Math.min(MAX_HEADER_SIZE, input.length));
        int headerLocation = initialPart.indexOf("Content-Encoding: gzip\r\n");
        if (headerLocation >= 0)
        {
            int bodyOffset = initialPart.indexOf(HEADER_BODY_SEPERATOR) + HEADER_BODY_SEPERATOR.length();
            if(headerLocation >= bodyOffset)
            {
                //The header that we found was actually in the body - so it's not gzip'ed after all
                return input;
            }

            ByteArrayOutputStream baos = new ByteArrayOutputStream(input.length);
            //Output the header verbatim
            baos.write(input, 0, bodyOffset);

            try {
                baos.write(new UncompressImpl(CompressionType.gzip, Arrays.copyOfRange(input, bodyOffset, input.length), null).uncompress());
                return baos.toByteArray();
            } catch (IOException e) {
                return input;
            }
        }

        return input;
    }

    /**
     * Removes the chunked encoding parts from applicable HTTP streams.
     *
     * @param input A byte array representing one side of the HTTP conversation.
     * @return The input without the additional chunked encoding parts littering
     * the body, or the original input if it's not a well formed chunked encoded HTTP stream.
     */
    public static byte[] stripChunkedEncoding(byte[] input)
    {
        final String HEADER_BODY_SEPERATOR = "\r\n\r\n";

        String initialPart = new String(input, 0, Math.min(MAX_HEADER_SIZE, input.length));
        int headerLocation = initialPart.toLowerCase().indexOf("transfer-encoding: chunked\r\n");
        if (headerLocation >= 0)
        {
            int bodyOffset = initialPart.indexOf(HEADER_BODY_SEPERATOR) + HEADER_BODY_SEPERATOR.length();
            if(headerLocation >= bodyOffset)
            {
                //The header that we found was actually in the body - so it's not chunk encoded after all
                return input;
            }

            ByteArrayOutputStream baos = new ByteArrayOutputStream(input.length);
            baos.write(input, 0, bodyOffset);

            ByteArrayInputStream bais = new ByteArrayInputStream(input, bodyOffset, input.length - bodyOffset);
            byte nextByte = 0;

            //Until we've processed all of the input
            while(nextByte != -1)
            {
                StringBuffer hexBuffer = new StringBuffer(100);

                //Stop parsing the length bytes when we hit a non-hex char
                while(nextByte != (byte)'\r' && nextByte != (byte)';')
                {
                    nextByte = (byte) bais.read();
                    hexBuffer.append((char)nextByte);
                    if(hexBuffer.length() > 99)
                    {
                        //We shouldn't be dealing with this much hex - something is wrong
                        return input;
                    }
                }
                //Consume up to the \n
                while(nextByte != (byte)'\n' )
                {
                    nextByte = (byte) bais.read();
                }

                //Trim the last character now we've established it's not hex
                hexBuffer.setLength(hexBuffer.length() - 1);
                int chunkSize = Integer.parseInt(hexBuffer.toString(), 16);
                if (chunkSize == 0)
                {
                    //There may be some trailers at this point - but we've nowhere to put them, so drop them
                    return baos.toByteArray();
                }

                try {
                    byte[] nextChunk = new byte[chunkSize];
                    bais.read(nextChunk);
                    baos.write(nextChunk);
                } catch (IOException e) {
                    e.printStackTrace(System.err);
                }

                if (bais.read() != (byte)'\r' || bais.read() != (byte)'\n') {
                    return input;
                }
            }

            return input;
        }
        else
        {
            return input;
        }
    }

}
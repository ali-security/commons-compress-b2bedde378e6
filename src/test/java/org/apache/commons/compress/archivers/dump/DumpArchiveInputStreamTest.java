/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.commons.compress.archivers.dump;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.apache.commons.compress.AbstractTestCase;
import org.apache.commons.compress.archivers.ArchiveEntry;
import org.apache.commons.compress.archivers.ArchiveException;
import org.apache.commons.compress.utils.IOUtils;
import org.junit.Test;

public class DumpArchiveInputStreamTest extends AbstractTestCase {

    @Test
    public void testNotADumpArchive() throws Exception {
        try (FileInputStream is = new FileInputStream(getFile("bla.zip"))) {
            new DumpArchiveInputStream(is).close();
            fail("expected an exception");
        } catch (final ArchiveException ex) {
            // expected
            assertTrue(ex.getCause() instanceof ShortFileException);
        }
    }

    @Test
    public void testNotADumpArchiveButBigEnough() throws Exception {
        try (FileInputStream is = new FileInputStream(getFile("zip64support.tar.bz2"))) {
            new DumpArchiveInputStream(is).close();
            fail("expected an exception");
        } catch (final ArchiveException ex) {
            // expected
            assertTrue(ex.getCause() instanceof UnrecognizedFormatException);
        }
    }

    @Test
    public void testConsumesArchiveCompletely() throws Exception {
        final InputStream is = DumpArchiveInputStreamTest.class
            .getResourceAsStream("/archive_with_trailer.dump");
        final DumpArchiveInputStream dump = new DumpArchiveInputStream(is);
        while (dump.getNextDumpEntry() != null) {
            // just consume the archive
        }
        final byte[] expected = new byte[] {
            'H', 'e', 'l', 'l', 'o', ',', ' ', 'w', 'o', 'r', 'l', 'd', '!', '\n'
        };
        final byte[] actual = new byte[expected.length];
        is.read(actual);
        assertArrayEquals(expected, actual);
        dump.close();
    }

    @Test
    public void singleByteReadConsistentlyReturnsMinusOneAtEof() throws Exception {
        try (FileInputStream in = new FileInputStream(getFile("bla.dump"));
             DumpArchiveInputStream archive = new DumpArchiveInputStream(in)) {
            ArchiveEntry e = archive.getNextEntry();
            IOUtils.toByteArray(archive);
            assertEquals(-1, archive.read());
            assertEquals(-1, archive.read());
        }
    }

    @Test
    public void multiByteReadConsistentlyReturnsMinusOneAtEof() throws Exception {
        byte[] buf = new byte[2];
        try (FileInputStream in = new FileInputStream(getFile("bla.dump"));
             DumpArchiveInputStream archive = new DumpArchiveInputStream(in)) {
            ArchiveEntry e = archive.getNextEntry();
            IOUtils.toByteArray(archive);
            assertEquals(-1, archive.read(buf));
            assertEquals(-1, archive.read(buf));
        }
    }

    @Test(timeout = 15000)
    public void testLoopingInodes() throws Exception {
        // directory inode 3 contains inode 4, directory inode 4 contains inode 3
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeArchiveHeaders(out);
        writeDirectory(out, 3, 4, "b", 1024);
        writeDirectory(out, 4, 3, "a", 1024);
        out.write(segmentHeader(DumpArchiveConstants.SEGMENT_TYPE.END, 0, 0, 0, 0));
        try (InputStream is = new ByteArrayInputStream(out.toByteArray());
             DumpArchiveInputStream archive = new DumpArchiveInputStream(is)) {
            try {
                archive.getNextEntry();
                fail("expected a DumpArchiveException");
            } catch (final DumpArchiveException ex) {
                assertTrue(ex.getMessage(), ex.getMessage().startsWith("Duplicate node"));
            }
        }
    }

    @Test(timeout = 20000)
    public void testRecLenZeroLongExecution() throws Exception {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeArchiveHeaders(out);
        writeDirectory(out, 2, 3, "a", 0);
        out.write(segmentHeader(DumpArchiveConstants.SEGMENT_TYPE.END, 0, 0, 0, 0));
        try (InputStream is = new ByteArrayInputStream(out.toByteArray());
             DumpArchiveInputStream archive = new DumpArchiveInputStream(is)) {
            try {
                archive.getNextEntry();
                fail("expected a DumpArchiveException");
            } catch (final DumpArchiveException ex) {
                assertEquals("reclen cannot be 0", ex.getMessage());
            }
        }
    }

    /**
     * Writes the TAPE, CLRI and BITS segments of an uncompressed dump archive
     * with one record per block.
     */
    private static void writeArchiveHeaders(final ByteArrayOutputStream out) throws Exception {
        final byte[] tape = new byte[DumpArchiveConstants.TP_SIZE];
        writeInt(tape, 0, 1); // SEGMENT_TYPE.TAPE
        writeInt(tape, 896, 1); // ntrec
        out.write(withChecksum(tape));
        out.write(segmentHeader(DumpArchiveConstants.SEGMENT_TYPE.CLRI, 0, 0, 0, 0));
        out.write(segmentHeader(DumpArchiveConstants.SEGMENT_TYPE.BITS, 0, 0, 0, 0));
    }

    /**
     * Writes a directory inode with a single data record containing one
     * directory entry.
     */
    private static void writeDirectory(final ByteArrayOutputStream out, final int dirIno, final int childIno,
        final String childName, final int reclen) throws Exception {
        out.write(segmentHeader(DumpArchiveConstants.SEGMENT_TYPE.INODE, dirIno, 040755,
            DumpArchiveConstants.TP_SIZE, 1));
        final byte[] data = new byte[DumpArchiveConstants.TP_SIZE];
        final byte[] name = childName.getBytes(StandardCharsets.US_ASCII);
        writeInt(data, 0, childIno);
        data[4] = (byte) (reclen & 0xff);
        data[5] = (byte) ((reclen >> 8) & 0xff);
        data[6] = 4; // DT_DIR
        data[7] = (byte) name.length;
        System.arraycopy(name, 0, data, 8, name.length);
        out.write(data);
    }

    private static byte[] segmentHeader(final DumpArchiveConstants.SEGMENT_TYPE type, final int ino,
        final int mode, final long size, final int count) {
        final byte[] header = new byte[DumpArchiveConstants.TP_SIZE];
        writeInt(header, 0, type.code);
        writeInt(header, 20, ino);
        header[32] = (byte) (mode & 0xff);
        header[33] = (byte) ((mode >> 8) & 0xff);
        writeInt(header, 40, (int) size);
        writeInt(header, 160, count);
        for (int i = 0; i < count; i++) {
            header[164 + i] = 1; // record present (not a hole)
        }
        return withChecksum(header);
    }

    private static byte[] withChecksum(final byte[] header) {
        writeInt(header, 24, DumpArchiveConstants.NFS_MAGIC);
        writeInt(header, 28, 0);
        writeInt(header, 28, DumpArchiveUtil.calculateChecksum(header));
        return header;
    }

    private static void writeInt(final byte[] buffer, final int offset, final int value) {
        buffer[offset] = (byte) (value & 0xff);
        buffer[offset + 1] = (byte) ((value >> 8) & 0xff);
        buffer[offset + 2] = (byte) ((value >> 16) & 0xff);
        buffer[offset + 3] = (byte) ((value >> 24) & 0xff);
    }

}

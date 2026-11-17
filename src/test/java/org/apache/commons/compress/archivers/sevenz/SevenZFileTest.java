/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.apache.commons.compress.archivers.sevenz;

import static org.junit.Assert.*;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Random;
import java.util.zip.CRC32;

import javax.crypto.Cipher;

import org.apache.commons.compress.AbstractTestCase;
import org.apache.commons.compress.PasswordRequiredException;
import org.apache.commons.compress.utils.IOUtils;
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.junit.Test;

public class SevenZFileTest extends AbstractTestCase {
    private static final String TEST2_CONTENT = "<?xml version = '1.0'?>\r\n<!DOCTYPE"
        + " connections>\r\n<meinxml>\r\n\t<leer />\r\n</meinxml>\n";

    // https://issues.apache.org/jira/browse/COMPRESS-320
    @Test
    public void testRandomlySkippingEntries() throws Exception {
        // Read sequential reference.
        final Map<String, byte[]> entriesByName = new HashMap<>();
        SevenZFile archive = new SevenZFile(getFile("COMPRESS-320/Copy.7z"));
        SevenZArchiveEntry entry;
        while ((entry = archive.getNextEntry()) != null) {
            if (entry.hasStream()) {
                entriesByName.put(entry.getName(), readFully(archive));
            }
        }
        archive.close();

        final String[] variants = {
            "BZip2-solid.7z",
            "BZip2.7z",
            "Copy-solid.7z",
            "Copy.7z",
            "Deflate-solid.7z",
            "Deflate.7z",
            "LZMA-solid.7z",
            "LZMA.7z",
            "LZMA2-solid.7z",
            "LZMA2.7z",
            // TODO: unsupported compression method.
            // "PPMd-solid.7z",
            // "PPMd.7z",
        };

        // TODO: use randomizedtesting for predictable, but different, randomness.
        final Random rnd = new Random(0xdeadbeef);
        for (final String fileName : variants) {
            archive = new SevenZFile(getFile("COMPRESS-320/" + fileName));

            while ((entry = archive.getNextEntry()) != null) {
                // Sometimes skip reading entries.
                if (rnd.nextBoolean()) {
                    continue;
                }

                if (entry.hasStream()) {
                    assertTrue(entriesByName.containsKey(entry.getName()));
                    final byte [] content = readFully(archive);
                    assertTrue("Content mismatch on: " + fileName + "!" + entry.getName(),
                               Arrays.equals(content, entriesByName.get(entry.getName())));
                }
            }

            archive.close();
        }
    }

    private byte[] readFully(final SevenZFile archive) throws IOException {
        final byte [] buf = new byte [1024];
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (int len = 0; (len = archive.read(buf)) > 0;) {
            baos.write(buf, 0, len);
        }
        return baos.toByteArray();
    }

    @Test
    public void testAllEmptyFilesArchive() throws Exception {
        try (SevenZFile archive = new SevenZFile(getFile("7z-empty-mhc-off.7z"))) {
            assertNotNull(archive.getNextEntry());
        }
    }

    @Test
    public void testHelloWorldHeaderCompressionOffCopy() throws Exception {
        checkHelloWorld("7z-hello-mhc-off-copy.7z");
    }

    @Test
    public void testHelloWorldHeaderCompressionOffLZMA2() throws Exception {
        checkHelloWorld("7z-hello-mhc-off-lzma2.7z");
    }

    @Test
    public void test7zUnarchive() throws Exception {
        test7zUnarchive(getFile("bla.7z"), SevenZMethod.LZMA);
    }

    @Test
    public void test7zDeflateUnarchive() throws Exception {
        test7zUnarchive(getFile("bla.deflate.7z"), SevenZMethod.DEFLATE);
    }

    @Test
    public void test7zDeflate64Unarchive() throws Exception {
        test7zUnarchive(getFile("bla.deflate64.7z"), SevenZMethod.DEFLATE64);
    }

    @Test
    public void test7zDecryptUnarchive() throws Exception {
        if (isStrongCryptoAvailable()) {
            test7zUnarchive(getFile("bla.encrypted.7z"), SevenZMethod.LZMA, // stack LZMA + AES
                            "foo".getBytes("UTF-16LE"));
        }
    }

    @Test
    public void test7zDecryptUnarchiveUsingCharArrayPassword() throws Exception {
        if (isStrongCryptoAvailable()) {
            test7zUnarchive(getFile("bla.encrypted.7z"), SevenZMethod.LZMA, // stack LZMA + AES
                            "foo".toCharArray());
        }
    }

    private void test7zUnarchive(final File f, final SevenZMethod m) throws Exception {
        test7zUnarchive(f, m, (char[]) null);
    }

    @Test
    public void testEncryptedArchiveRequiresPassword() throws Exception {
        try {
            new SevenZFile(getFile("bla.encrypted.7z")).close();
            fail("shouldn't decrypt without a password");
        } catch (final PasswordRequiredException ex) {
            final String msg = ex.getMessage();
            assertTrue("Should start with whining about being unable to decrypt",
                       msg.startsWith("Cannot read encrypted content from "));
            assertTrue("Should finish the sentence properly",
                       msg.endsWith(" without a password."));
            assertTrue("Should contain archive's name",
                       msg.contains("bla.encrypted.7z"));
        }
    }

    /**
     * @see "https://issues.apache.org/jira/browse/COMPRESS-256"
     */
    @Test
    public void testCompressedHeaderWithNonDefaultDictionarySize() throws Exception {
        try (SevenZFile sevenZFile = new SevenZFile(getFile("COMPRESS-256.7z"))) {
            int count = 0;
            while (sevenZFile.getNextEntry() != null) {
                count++;
            }
            assertEquals(446, count);
        }
    }

    @Test
    public void testSignatureCheck() {
        assertTrue(SevenZFile.matches(SevenZFile.sevenZSignature,
                                      SevenZFile.sevenZSignature.length));
        assertTrue(SevenZFile.matches(SevenZFile.sevenZSignature,
                                      SevenZFile.sevenZSignature.length + 1));
        assertFalse(SevenZFile.matches(SevenZFile.sevenZSignature,
                                      SevenZFile.sevenZSignature.length - 1));
        assertFalse(SevenZFile.matches(new byte[] { 1, 2, 3, 4, 5, 6 }, 6));
        assertTrue(SevenZFile.matches(new byte[] { '7', 'z', (byte) 0xBC,
                                                   (byte) 0xAF, 0x27, 0x1C}, 6));
        assertFalse(SevenZFile.matches(new byte[] { '7', 'z', (byte) 0xBC,
                                                    (byte) 0xAF, 0x27, 0x1D}, 6));
    }

    @Test
    public void testReadingBackLZMA2DictSize() throws Exception {
        final File output = new File(dir, "lzma2-dictsize.7z");
        try (SevenZOutputFile outArchive = new SevenZOutputFile(output)) {
            outArchive.setContentMethods(Arrays.asList(new SevenZMethodConfiguration(SevenZMethod.LZMA2, 1 << 20)));
            final SevenZArchiveEntry entry = new SevenZArchiveEntry();
            entry.setName("foo.txt");
            outArchive.putArchiveEntry(entry);
            outArchive.write(new byte[] { 'A' });
            outArchive.closeArchiveEntry();
        }

        try (SevenZFile archive = new SevenZFile(output)) {
            final SevenZArchiveEntry entry = archive.getNextEntry();
            final SevenZMethodConfiguration m = entry.getContentMethods().iterator().next();
            assertEquals(SevenZMethod.LZMA2, m.getMethod());
            assertEquals(1 << 20, m.getOptions());
        }
    }

    @Test
    public void testReadingBackDeltaDistance() throws Exception {
        final File output = new File(dir, "delta-distance.7z");
        try (SevenZOutputFile outArchive = new SevenZOutputFile(output)) {
            outArchive.setContentMethods(Arrays.asList(new SevenZMethodConfiguration(SevenZMethod.DELTA_FILTER, 32),
                    new SevenZMethodConfiguration(SevenZMethod.LZMA2)));
            final SevenZArchiveEntry entry = new SevenZArchiveEntry();
            entry.setName("foo.txt");
            outArchive.putArchiveEntry(entry);
            outArchive.write(new byte[] { 'A' });
            outArchive.closeArchiveEntry();
        }

        try (SevenZFile archive = new SevenZFile(output)) {
            final SevenZArchiveEntry entry = archive.getNextEntry();
            final SevenZMethodConfiguration m = entry.getContentMethods().iterator().next();
            assertEquals(SevenZMethod.DELTA_FILTER, m.getMethod());
            assertEquals(32, m.getOptions());
        }
    }

    @Test
    public void getEntriesOfUnarchiveTest() throws IOException {
        try (SevenZFile sevenZFile = new SevenZFile(getFile("bla.7z"))) {
            final Iterable<SevenZArchiveEntry> entries = sevenZFile.getEntries();
            final Iterator<SevenZArchiveEntry> iter = entries.iterator();
            SevenZArchiveEntry entry = iter.next();
            assertEquals("test1.xml", entry.getName());
            entry = iter.next();
            assertEquals("test2.xml", entry.getName());
            assertFalse(iter.hasNext());
        }
    }

    @Test
    public void getEntriesOfUnarchiveInMemoryTest() throws IOException {
        byte[] data = null;
        try (FileInputStream fis = new FileInputStream(getFile("bla.7z"))) {
            data = IOUtils.toByteArray(fis);
        }
        try (SevenZFile sevenZFile = new SevenZFile(new SeekableInMemoryByteChannel(data))) {
            final Iterable<SevenZArchiveEntry> entries = sevenZFile.getEntries();
            final Iterator<SevenZArchiveEntry> iter = entries.iterator();
            SevenZArchiveEntry entry = iter.next();
            assertEquals("test1.xml", entry.getName());
            entry = iter.next();
            assertEquals("test2.xml", entry.getName());
            assertFalse(iter.hasNext());
        }
    }

    /**
     * @see "https://issues.apache.org/jira/browse/COMPRESS-348"
     */
    @Test
    public void readEntriesOfSize0() throws IOException {
        try (SevenZFile sevenZFile = new SevenZFile(getFile("COMPRESS-348.7z"))) {
            int entries = 0;
            SevenZArchiveEntry entry = sevenZFile.getNextEntry();
            while (entry != null) {
                entries++;
                final int b = sevenZFile.read();
                if ("2.txt".equals(entry.getName()) || "5.txt".equals(entry.getName())) {
                    assertEquals(-1, b);
                } else {
                    assertNotEquals(-1, b);
                }
                entry = sevenZFile.getNextEntry();
            }
            assertEquals(5, entries);
        }
    }

    private void test7zUnarchive(final File f, final SevenZMethod m, final byte[] password) throws Exception {
        try (SevenZFile sevenZFile = new SevenZFile(f, password)) {
            test7zUnarchive(sevenZFile, m);
        }
    }

    private void test7zUnarchive(final File f, final SevenZMethod m, final char[] password) throws Exception {
        try (SevenZFile sevenZFile = new SevenZFile(f, password)) {
            test7zUnarchive(sevenZFile, m);
        }
    }

    private void test7zUnarchive(SevenZFile sevenZFile, final SevenZMethod m) throws Exception {
        SevenZArchiveEntry entry = sevenZFile.getNextEntry();
        assertEquals("test1.xml", entry.getName());
        assertEquals(m, entry.getContentMethods().iterator().next().getMethod());
        entry = sevenZFile.getNextEntry();
        assertEquals("test2.xml", entry.getName());
        assertEquals(m, entry.getContentMethods().iterator().next().getMethod());
        final byte[] contents = new byte[(int) entry.getSize()];
        int off = 0;
        while ((off < contents.length)) {
            final int bytesRead = sevenZFile.read(contents, off, contents.length - off);
            assert (bytesRead >= 0);
            off += bytesRead;
        }
        assertEquals(TEST2_CONTENT, new String(contents, "UTF-8"));
        assertNull(sevenZFile.getNextEntry());
    }

    private void checkHelloWorld(final String filename) throws Exception {
        try (SevenZFile sevenZFile = new SevenZFile(getFile(filename))) {
            final SevenZArchiveEntry entry = sevenZFile.getNextEntry();
            assertEquals("Hello world.txt", entry.getName());
            final byte[] contents = new byte[(int) entry.getSize()];
            int off = 0;
            while ((off < contents.length)) {
                final int bytesRead = sevenZFile.read(contents, off, contents.length - off);
                assert (bytesRead >= 0);
                off += bytesRead;
            }
            assertEquals("Hello, world!\n", new String(contents, "UTF-8"));
            assertNull(sevenZFile.getNextEntry());
        }
    }

    @Test
    public void rejectsNextHeaderSizeBeyondEndOfArchive() throws Exception {
        // claims a 2 GB header inside an archive of a few bytes
        assertArchiveIsRejected(createArchive(new byte[0], 0, 0x7FFFFFF0L, new byte[0]),
            "nextHeaderSize is out of bounds");
    }

    @Test
    public void rejectsNextHeaderOffsetBeyondEndOfArchive() throws Exception {
        assertArchiveIsRejected(createArchive(new byte[0], 0x7FFFFFF0L, 0, new byte[0]),
            "nextHeaderOffset is out of bounds");
    }

    @Test
    public void rejectsArchivePropertyLargerThanHeader() throws Exception {
        final ByteArrayOutputStream header = new ByteArrayOutputStream();
        header.write(NID.kHeader);
        header.write(NID.kArchiveProperties);
        header.write(1); // property type
        writeUint64(header, 0x7FFFFFF0L); // property size
        header.write(NID.kEnd);
        header.write(NID.kEnd);
        assertArchiveIsRejected(createArchive(new byte[0], header.toByteArray()), "invalid property size");
    }

    @Test
    public void rejectsHugeNumberOfFilesWithoutFolders() throws Exception {
        final ByteArrayOutputStream header = new ByteArrayOutputStream();
        header.write(NID.kHeader);
        header.write(NID.kFilesInfo);
        writeUint64(header, 0x7FFFFFF0L); // number of files
        header.write(NID.kEnd); // no file properties
        header.write(NID.kEnd);
        assertArchiveIsRejected(createArchive(new byte[0], header.toByteArray()),
            "archive with entries but no folders");
    }

    @Test
    public void rejectsHugeNumberOfCoders() throws Exception {
        final ByteArrayOutputStream header = new ByteArrayOutputStream();
        header.write(NID.kHeader);
        header.write(NID.kMainStreamsInfo);
        writePackInfo(header, 0);
        header.write(NID.kUnpackInfo);
        header.write(NID.kFolder);
        writeUint64(header, 1); // number of folders
        header.write(0); // not external
        writeUint64(header, 0x7FFFFFF0L); // number of coders
        header.write(0x01); // simple coder with one byte method id
        header.write(0x00); // COPY
        header.write(NID.kEnd);
        assertArchiveIsRejected(createArchive(new byte[0], header.toByteArray()), "truncated");
    }

    @Test
    public void rejectsHugeNumberOfSubStreamsWithoutSizes() throws Exception {
        final ByteArrayOutputStream header = new ByteArrayOutputStream();
        header.write(NID.kHeader);
        header.write(NID.kMainStreamsInfo);
        writePackInfo(header, 0);
        writeSingleCopyFolderUnpackInfo(header, 0);
        header.write(NID.kSubStreamsInfo);
        header.write(NID.kNumUnpackStream);
        writeUint64(header, 0x7FFFFFF0L); // number of sub streams in the folder
        header.write(NID.kEnd);
        header.write(NID.kEnd); // end of streams info
        header.write(NID.kEnd);
        assertArchiveIsRejected(createArchive(new byte[0], header.toByteArray()),
            "missing unpack sizes for sub streams");
    }

    @Test
    public void rejectsEncodedHeaderWithHugeUnpackSize() throws Exception {
        final byte[] packed = new byte[] { 1, 2, 3, 4 };
        final ByteArrayOutputStream header = new ByteArrayOutputStream();
        header.write(NID.kEncodedHeader);
        writePackInfo(header, packed.length);
        writeSingleCopyFolderUnpackInfo(header, 0x7FFFFFF0L);
        header.write(NID.kEnd); // end of streams info
        assertArchiveIsRejected(createArchive(packed, header.toByteArray()), "premature end of stream");
    }

    @Test(timeout = 30000)
    public void rejectsEncodedHeaderWithCyclicCoderChain() throws Exception {
        final byte[] packed = new byte[] { 1, 2, 3, 4 };
        final ByteArrayOutputStream header = new ByteArrayOutputStream();
        header.write(NID.kEncodedHeader);
        writePackInfo(header, packed.length);
        header.write(NID.kUnpackInfo);
        header.write(NID.kFolder);
        writeUint64(header, 1); // number of folders
        header.write(0); // not external
        writeUint64(header, 2); // number of coders
        header.write(0x11); // complex coder with one byte method id
        header.write(0x00); // COPY
        writeUint64(header, 2); // numInStreams
        writeUint64(header, 1); // numOutStreams
        header.write(0x01); // simple coder with one byte method id
        header.write(0x00); // COPY
        // single bind pair binding coder 0's output to its own input
        writeUint64(header, 0); // inIndex
        writeUint64(header, 0); // outIndex
        writeUint64(header, 0); // packed stream index
        writeUint64(header, 0); // packed stream index
        header.write(NID.kCodersUnpackSize);
        writeUint64(header, packed.length);
        writeUint64(header, packed.length);
        header.write(NID.kEnd);
        header.write(NID.kEnd); // end of streams info
        assertArchiveIsRejected(createArchive(packed, header.toByteArray()),
            "same coder more than once");
    }

    private static void assertArchiveIsRejected(final byte[] archive, final String expectedMessage)
        throws Exception {
        try (SevenZFile sevenZFile = new SevenZFile(new SeekableInMemoryByteChannel(archive))) {
            fail("expected archive to be rejected");
        } catch (final IOException ex) {
            assertTrue("unexpected message: " + ex.getMessage(),
                ex.getMessage().contains(expectedMessage));
        }
    }

    private static void writePackInfo(final ByteArrayOutputStream header, final long packSize) {
        header.write(NID.kPackInfo);
        writeUint64(header, 0); // packPos
        writeUint64(header, 1); // number of pack streams
        header.write(NID.kSize);
        writeUint64(header, packSize);
        header.write(NID.kEnd);
    }

    private static void writeSingleCopyFolderUnpackInfo(final ByteArrayOutputStream header,
        final long unpackSize) {
        header.write(NID.kUnpackInfo);
        header.write(NID.kFolder);
        writeUint64(header, 1); // number of folders
        header.write(0); // not external
        writeUint64(header, 1); // number of coders
        header.write(0x01); // simple coder with one byte method id
        header.write(0x00); // COPY
        header.write(NID.kCodersUnpackSize);
        writeUint64(header, unpackSize);
        header.write(NID.kEnd);
    }

    private static byte[] createArchive(final byte[] packed, final byte[] header) {
        final byte[] body = new byte[packed.length + header.length];
        System.arraycopy(packed, 0, body, 0, packed.length);
        System.arraycopy(header, 0, body, packed.length, header.length);
        return createArchive(body, packed.length, header.length, header);
    }

    private static byte[] createArchive(final byte[] body, final long nextHeaderOffset,
        final long nextHeaderSize, final byte[] header) {
        final ByteBuffer buf = ByteBuffer.allocate(SevenZFile.SIGNATURE_HEADER_SIZE + body.length)
            .order(ByteOrder.LITTLE_ENDIAN);
        buf.put(SevenZFile.sevenZSignature);
        buf.put((byte) 0);
        buf.put((byte) 4);
        buf.putInt(0); // start header CRC, filled in below
        buf.putLong(nextHeaderOffset);
        buf.putLong(nextHeaderSize);
        final CRC32 headerCrc = new CRC32();
        headerCrc.update(header);
        buf.putInt((int) headerCrc.getValue());
        final CRC32 startHeaderCrc = new CRC32();
        startHeaderCrc.update(buf.array(), 12, 20);
        buf.putInt(8, (int) startHeaderCrc.getValue());
        buf.put(body);
        return buf.array();
    }

    private static void writeUint64(final ByteArrayOutputStream out, long value) {
        int firstByte = 0;
        int mask = 0x80;
        int i;
        for (i = 0; i < 8; i++) {
            if (value < ((1L << ( 7  * (i + 1))))) {
                firstByte |= (value >>> (8 * i));
                break;
            }
            firstByte |= mask;
            mask >>>= 1;
        }
        out.write(firstByte);
        for (; i > 0; i--) {
            out.write((int) (0xff & value));
            value >>>= 8;
        }
    }

    private static boolean isStrongCryptoAvailable() throws NoSuchAlgorithmException {
        return Cipher.getMaxAllowedKeyLength("AES/ECB/PKCS5Padding") >= 256;
    }
}

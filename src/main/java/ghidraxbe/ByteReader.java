package ghidraxbe;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import ghidra.app.util.bin.ByteProvider;

/**
 * Byte-level reader interface.
 *
 * This class allows reading little-endian encoded values from a byte-oriented
 * stream.
 *
 * @author Jonas Schievink
 */
public class ByteReader extends InputStream {
    private ByteProvider bytes;
    private InputStream stream;
    private long baseAddr = 0;

    public ByteReader(ByteProvider bytes) throws IOException {
	this.bytes = bytes;
	this.stream = bytes.getInputStream(0);
    }

    private static ByteBuffer buf(byte[] bytes) {
	return ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
    }

    /**
     * Reads a little-endian 32-bit integer from the stream.
     */
    public int readInt32() throws IOException {
	byte[] bytes = this.stream.readNBytes(4);
	return buf(bytes).getInt();
    }

    @Override
    public int read() throws IOException {
	return stream.read();
    }

    /**
     * Returns a new ByteReader operating on the same data, but with its position
     * moved to base-relative address `addr`.
     *
     * `addr` is relative to the configured base address.
     *
     * This should be used when the address is actually relative to the XBEs base
     * address, which is the case for most addresses in the headers.
     */
    public ByteReader seeked(long addr) throws IOException {
	return this.seekedRaw(addr - baseAddr);
    }

    /**
     * Returns a new ByteReader that is seeked to an absolute, raw address.
     */
    public ByteReader seekedRaw(long rawAddr) throws IOException {
	ByteReader r = new ByteReader(this.bytes);
	r.baseAddr = this.baseAddr;
	r.stream = bytes.getInputStream(rawAddr);
	return r;
    }

    /**
     * Returns a new ByteReader that limits the number of bytes that can be read
     * from it.
     *
     * @param limit The max. number of bytes to read through the created reader.
     */
    public ByteReader limited(long limit) throws IOException {
	ByteReader r = new ByteReader(this.bytes);
	r.baseAddr = this.baseAddr;
	r.stream = new InputStream() {
	    long bytesRead = 0;

	    @Override
	    public int read() throws IOException {
		if (bytesRead >= limit) {
		    return -1;
		} else {
		    bytesRead++;
		    return ByteReader.this.stream.read();
		}
	    }
	};
	return r;
    }

    /**
     * Sets the reader's base address.
     *
     * This address is used as the base address of seek operations (meaning that
     * `seek(16)` is turned into `seek(16 - base)`).
     *
     * @param addr The base address
     */
    public void baseAddr(long addr) {
	this.baseAddr = addr;
    }
}

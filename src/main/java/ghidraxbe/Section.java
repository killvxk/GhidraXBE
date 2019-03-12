package ghidraxbe;

import java.io.IOException;
import java.io.InputStream;

/**
 * A parsed XBE section header.
 *
 * @author Jonas Schievink
 */
public class Section {
    public static final int FLAGS_WRITABLE = 0x1;
    public static final int FLAGS_EXECUTABLE = 0x4;

    private int flags, virtAddr, virtSize, rawAddr, rawSize;
    private String name;
    private InputStream data;

    public Section(ByteReader r) throws IOException {
	this.flags = r.readInt32();
	this.virtAddr = r.readInt32();
	this.virtSize = r.readInt32();
	this.rawAddr = r.readInt32();
	this.rawSize = r.readInt32();
	int nameAddr = r.readInt32();
	// ... rest isn't used, but we have to read it to advance the reader
	r.readInt32(); // section name refcount
	r.readInt32(); // head_shared_page_refcount_addr
	r.readInt32(); // tail_shared_page_refcount_addr
	r.skip(20); // signature digest

	// Read the section name (0-terminated)
	ByteReader nameReader = r.seeked(nameAddr);
	StringBuffer name = new StringBuffer();
	int b;
	while ((b = nameReader.read()) != -1) {
	    if (b == 0)
		break;
	    char c = (char) (b);
	    name.append(c);
	}
	this.name = name.toString();

	System.out.println(String.format("section '%s' from 0x%x..0x%x -> 0x%x..0x%x", this.name, rawAddr,
		rawAddr + rawSize, virtAddr, virtAddr + virtSize));

	this.data = r.seekedRaw(this.rawAddr).limited(this.rawSize);
    }

    public String name() {
	return this.name;
    }

    public InputStream data() {
	return this.data;
    }

    public long virtAddr() {
	return this.virtAddr;
    }

    public long virtSize() {
	return this.virtSize;
    }

    /**
     * Gets the flags field of the section.
     *
     * Known flags are available as constants in this class.
     *
     * @return Section flags
     */
    public int flags() {
	return this.flags;
    }
}

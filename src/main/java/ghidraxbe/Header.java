package ghidraxbe;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * The XBE header structures.
 *
 * Most of the code is ported from my XBE crate:
 * https://github.com/jonas-schievink/xbe
 *
 * @author Jonas Schievink
 */
public class Header {
    private static final int MAGIC = 0x48454258; // "XBEH"

    private static final int ENTRY_XOR_DEBUG = 0x94859D4B;
    private static final int ENTRY_XOR_RETAIL = 0xA8FC57AB;
    private static final int THUNK_XOR_DEBUG = 0xEFB1F152;
    private static final int THUNK_XOR_RETAIL = 0x5B6D40B6;

    // The header area of the XBE file
    private byte[] rawHeaders;
    private int baseAddr;
    private int entryPoint;
    private int thunkTableAddr;
    private boolean isDebug;
    private List<Section> sections;

    public Header(ByteReader r) throws IOException, ParsingException {
	int magic = r.readInt32();
	if (magic != MAGIC) {
	    throw new ParsingException(String.format("invalid magic number 0x%x", magic));
	}

	// 256 Byte Signature
	r.skip(256);

	baseAddr = r.readInt32();
	r.baseAddr(baseAddr);
	int headerSize = r.readInt32(); // header size
	r.readInt32(); // image size
	r.readInt32(); // image header size
	r.readInt32(); // creation timestamp
	r.readInt32(); // certificate addr
	int numSections = r.readInt32();
	int sectionHeaderAddr = r.readInt32(); // addr of section headers
	r.readInt32(); // init flags
	int encodedEntryPoint = r.readInt32(); // entry point
	r.readInt32(); // tls addr
	r.readInt32(); // PE stack commit
	r.readInt32(); // PE heap reserve
	r.readInt32(); // PE heap commit
	r.readInt32(); // PE base addr
	r.readInt32(); // PE header size
	r.readInt32(); // PE checksum
	r.readInt32(); // PE time date
	r.readInt32(); // debug pathname addr
	r.readInt32(); // debug filename addr
	r.readInt32(); // debug unicode filename addr
	int encodedThunkAddr = r.readInt32();
	// ...more stuff we don't need

	// Read the raw header data
	rawHeaders = r.seekedRaw(0).readNBytes(headerSize);

	// Parse section table
	this.sections = new ArrayList<>();
	ByteReader secReader = r.seeked(sectionHeaderAddr);
	for (int i = 0; i < numSections; i++) {
	    this.sections.add(new Section(secReader));
	}

	// Decode XORd addresses
	int thunkAddr;
	if (addrInBounds(encodedThunkAddr ^ THUNK_XOR_RETAIL) && addrInBounds(encodedEntryPoint ^ ENTRY_XOR_RETAIL)) {
	    thunkAddr = encodedThunkAddr ^ THUNK_XOR_RETAIL;
	    entryPoint = encodedEntryPoint ^ ENTRY_XOR_RETAIL;
	    System.out.println(String.format("Retail image; thunk=0x%X, entry=0x%X", thunkAddr, entryPoint));
	} else if (addrInBounds(encodedThunkAddr ^ THUNK_XOR_DEBUG)
		&& addrInBounds(encodedEntryPoint ^ ENTRY_XOR_DEBUG)) {
	    thunkAddr = encodedThunkAddr ^ THUNK_XOR_DEBUG;
	    entryPoint = encodedEntryPoint ^ ENTRY_XOR_DEBUG;
	    System.out.println(String.format("Debug image; thunk=0x%X, entry=0x%X", thunkAddr, entryPoint));
	} else {
	    throw new ParsingException("Couldn't determine image kind");
	}

	this.thunkTableAddr = thunkAddr;
    }

    /**
     * Checks whether the given address is inside a valid section
     */
    private boolean addrInBounds(int addr) {
	for (Section s : this.sections) {
	    if (s.virtAddr() <= addr && s.virtAddr() + s.virtSize() >= addr)
		return true;
	}

	return false;
    }

    public int baseAddr() {
	return this.baseAddr;
    }

    public int entryPoint() {
	return this.entryPoint;
    }

    public int thunkTableAddr() {
	return this.thunkTableAddr;
    }

    public List<Section> sections() {
	return this.sections;
    }

    /**
     * Whether this image is a debug image.
     *
     * An XBE is either made for debug consoles or (most frequently) for retail
     * consoles. The image kind is inferred from the encoding of entry point and
     * thunk table address.
     *
     * @return true if this is a debug image, false if it's a retail image.
     */
    public boolean isDebug() {
	return this.isDebug;
    }

    /**
     * Returns the raw XBE header data.
     *
     * This data should be mapped at {@link Header#baseAddr()} in the system's
     * address space.
     *
     * @return XBE header data
     */
    public byte[] rawHeaderData() {
	return this.rawHeaders;
    }
}

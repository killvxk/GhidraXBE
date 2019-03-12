/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidraxbe;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * A loader for `.xbe` files (The executable file format used by the original
 * Xbox).
 *
 * @author Jonas Schievink
 */
public class GhidraXBELoader extends AbstractLibrarySupportLoader {
    @Override
    public String getName() {
	return "Xbox Executable (XBE)";
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
	List<LoadSpec> loadSpecs = new ArrayList<>();

	// Examine the bytes in 'provider' to determine if this loader can load
	// it. If it can load it, return the appropriate load specifications.
	System.out.println("XBELoader trying " + provider.getName());
	try {
	    // We try to parse the header, which checks the magic number. If that works,
	    // this is very likely to be an XBE.
	    Header h = new Header(new ByteReader(provider));
	    loadSpecs.add(new LoadSpec(this, h.baseAddr(), new LanguageCompilerSpecPair("x86:LE:32:default", "windows"),
		    true));
	    System.out.println("XBELoader can load this!");
	} catch (IOException e) {
	    System.err.println("XBELoader IOException: " + e);
	    e.printStackTrace();
	    throw e;
	} catch (ParsingException e) {
	    System.out.println("Couldn't parse " + provider.getName() + " as XBE file: " + e.toString());
	}

	return loadSpecs;
    }

    @Override
    protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
	    MemoryConflictHandler handler, TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {
	// Load the bytes from 'provider' into the 'program'. Specifically:
	// * Set up all memory maps (XBE headers and sections)
	// * Set the image base as specified in the XBE header
	// * Mark the entry point as an external entry point, and add a label for it
	// * Add labels for all imported kernel functions
	try {
	    System.out.println("XBELoader loading: " + program.getAddressMap());
	    ByteReader r = new ByteReader(provider);
	    Header h = new Header(r);

	    AddressSpace space = program.getAddressFactory().getAddressSpace("ram");
	    if (space == null) {
		throw new NullPointerException("no RAM address space!");
	    }

	    // map XBE headers
	    Address baseAddr = space.getAddress(h.baseAddr());
	    MemoryBlock headerBlock = program.getMemory().createInitializedBlock("<XBE headers>", baseAddr,
		    new ByteArrayInputStream(h.rawHeaderData()), h.rawHeaderData().length, monitor, false);
	    headerBlock.setWrite(true);
	    // FIXME not actually sure what the default perms are, but the code writes to
	    // it, so it's at least writable
	    // FIXME consider adding labels for all the header fields - might make
	    // disassembly output much more readable

	    Address thunkTableAddr = space.getAddress(h.thunkTableAddr());

	    // map all sections
	    for (Section s : h.sections()) {
		Address addr = space.getAddress(s.virtAddr());
		MemoryBlock block = program.getMemory().createInitializedBlock(s.name(), addr, s.data(), s.virtSize(),
			monitor, false);
		if (block.contains(thunkTableAddr)) {
		    // FIXME: Kernel calls only show up "properly" when the thunk section is
		    // writable and executable, so we always force those permissions on.
		    block.setWrite(true);
		    block.setExecute(true);
		} else {
		    if ((s.flags() & Section.FLAGS_WRITABLE) != 0) {
			block.setWrite(true);
		    }
		    if ((s.flags() & Section.FLAGS_EXECUTABLE) != 0) {
			block.setExecute(true);
		    }
		}
	    }
	    System.out.println("XBELoader: Loaded sections into memory");

	    program.setImageBase(space.getAddress(h.baseAddr()), true);

	    // set entry point
	    Address entryPoint = space.getAddress(h.entryPoint());
	    program.getSymbolTable().addExternalEntryPoint(entryPoint);
	    program.getSymbolTable().createLabel(entryPoint, "entry", SourceType.ANALYSIS);
	    // FIXME where's "createFunction"? There only seems to be "createLabel"

	    // the thunk table address refers to virtual memory, so we had to set that up
	    // before parsing the thunk table
	    ThunkTable thunks = new ThunkTable(thunkTableAddr, program.getMemory());

	    // now add all imported library functions, here that's just the kernel functions
	    System.out.println("Processing " + thunks.entries().size() + " kernel imports");
	    for (ThunkTable.Entry entry : thunks.entries()) {
		Address addr = space.getAddress(entry.address());
		program.getSymbolTable().createLabel(addr, entry.name(), SourceType.IMPORTED);

		byte[] bytes = new byte[4];
		program.getMemory().getBytes(addr, bytes);

		// FIXME kernel function calls still don't show up *perfectly*. They're
		// decompiled as:
		// (*_KeFunction)(arg0, arg1, ...)
	    }
	} catch (ParsingException | LockException | MemoryConflictException | AddressOverflowException
		| DuplicateNameException | AddressOutOfBoundsException | InvalidInputException
		| MemoryAccessException e) {
	    e.printStackTrace();
	    throw new IOException(e);
	} catch (IOException io) {
	    io.printStackTrace();
	    throw io;
	}
    }
}

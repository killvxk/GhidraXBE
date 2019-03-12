package ghidraxbe;

/**
 * An exception type thrown when parsing data in an XBE file failed.
 *
 * This exception indicates that the input file is malformed or not and XBE
 * file.
 *
 * @author Jonas Schievink
 */
public class ParsingException extends Exception {
    public ParsingException(String message) {
	super(message);
    }
}

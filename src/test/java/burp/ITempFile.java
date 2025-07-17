package burp;

import java.io.File;

public interface ITempFile {
    byte[] getBuffer();
    void delete();
    File getFile();
}
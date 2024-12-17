package Main;

import javacard.framework.Shareable;
import javacard.security.AESKey;

public interface AesShareable extends Shareable {
    AESKey getAesKey();
}

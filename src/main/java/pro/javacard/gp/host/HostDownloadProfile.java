/*
 * gpj - Global Platform for Java SmartCardIO
 *
 * Copyright (C) 2009 Wojciech Mostowski, woj@cs.ru.nl
 * Copyright (C) 2009 Francois Kooman, F.Kooman@student.science.ru.nl
 * Copyright (C) 2014-2017 Martin Paljak, martin@martinpaljak.net
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 */

package pro.javacard.gp.host;

import apdu4j.HexUtils;
import apdu4j.ISO7816;
import com.payneteasy.tlv.BerTag;
import com.payneteasy.tlv.BerTlv;
import com.payneteasy.tlv.BerTlvParser;
import com.payneteasy.tlv.BerTlvs;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pro.javacard.AID;
import pro.javacard.CAPFile;
import pro.javacard.gp.GPException;
import pro.javacard.gp.GPKey.Type;
import pro.javacard.gp.GPRegistryEntry.Kind;
import pro.javacard.gp.GPRegistryEntry.Privilege;
import pro.javacard.gp.GPRegistryEntry.Privileges;
import pro.javacard.gp.GPSessionKeyProvider;
import pro.javacard.gp.profiledownload.InitializeUpdateResponseApdu;

  import javax.crypto.Cipher;
import javax.smartcardio.*;
import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

public class HostDownloadProfile {
    private static final Logger LOGGER = LoggerFactory.getLogger(HostDownloadProfile.class);
    private static final byte CLA_GP = (byte) 0x80;
    private static final byte INS_INITIALIZE_UPDATE = (byte) 0x50;

//    public static final int SCP_ANY = 0;

//    public static final EnumSet<APDUMode> defaultMode = EnumSet.of(APDUMode.MAC);
//    public static final byte CLA_MAC = (byte) 0x84;
//
//    public static final byte INS_INSTALL = (byte) 0xE6;
//    public static final byte INS_LOAD = (byte) 0xE8;
//    public static final byte INS_DELETE = (byte) 0xE4;
//    public static final byte INS_GET_STATUS = (byte) 0xF2;
//    public static final byte INS_SET_STATUS = (byte) 0xF0;
//    public static final byte INS_PUT_KEY = (byte) 0xD8;
//    public static final byte INS_STORE_DATA = (byte) 0xE2;
//    public static final byte INS_GET_DATA = (byte) 0xCA;
//
//    public static final byte P1_INSTALL_AND_MAKE_SELECTABLE = (byte) 0x0C;
//    public static final byte P1_INSTALL_FOR_INSTALL = (byte) 0x04;
//
    private GPCrypto gpCrypto;
    private byte[] hostChallenge;
//    protected boolean strict = true;
//    GPSpec spec = GPSpec.GP211;
//
//    // (I)SD AID successfully selected or null
//    private AID sdAID = null;
//    // Either 1 or 2 or 3
//    private int scpMajorVersion = 0;
//    private int scpKeyVersion = 0;
//
//    private int blockSize = 255;
//    private GPSessionKeyProvider sessionKeys = null;
//    private SecureChannelWrapper wrapper = null;
//    private CardChannel channel;
//    private GPRegistry registry = null;
//    private boolean dirty = true; // True if registry is dirty.

    public HostDownloadProfile() {

        gpCrypto = new GPCrypto();
    }

//    private void parse_select_response(byte[] fci) throws GPException {
//        final BerTlvs tlvs;
//        try {
//            BerTlvParser parser = new BerTlvParser();
//            tlvs = parser.parse(fci);
//            GPUtils.trace_tlv(fci, logger);
//        } catch (ArrayIndexOutOfBoundsException | IllegalStateException e) {
//            logger.warn("Could not parse SELECT response: " + e.getMessage());
//            return;
//        }
//        BerTlv fcitag = tlvs.find(new BerTag(0x6F));
//        if (fcitag != null) {
//            BerTlv isdaid = fcitag.find(new BerTag(0x84));
//            if (isdaid != null) {
//                AID detectedAID = new AID(isdaid.getBytesValue());
//                if (!detectedAID.equals(sdAID)) {
//                    logger.warn(String.format("SD AID in FCI (%s) does not match the requested AID (%s). Using reported AID!", detectedAID, sdAID));
//                    // So one can select only the prefix
//                    sdAID = detectedAID;
//                }
//            }
//
//            //
//            BerTlv prop = fcitag.find(new BerTag(0xA5));
//            if (prop != null) {
//
//                BerTlv isdd = prop.find(new BerTag(0x73));
//                if (isdd != null) {
//                    // Tag 73 is a constructed tag.
//                    BerTlv oidtag = isdd.find(new BerTag(0x06));
//                    if (oidtag != null) {
//                        if (Arrays.equals(oidtag.getBytesValue(), HexUtils.hex2bin("2A864886FC6B01"))) {
//                            // Detect versions
//                            BerTlv vertag = isdd.find(new BerTag(0x60));
//                            if (vertag != null) {
//                                BerTlv veroid = vertag.find(new BerTag(0x06));
//                                if (veroid != null) {
//                                    spec = GPData.oid2version(veroid.getBytesValue());
//                                    logger.debug("Auto-detected GP version: " + spec);
//                                }
//                            }
//                        } else {
//                            throw new GPDataException("Invalid CardRecognitionData", oidtag.getBytesValue());
//                        }
//                    } else {
//                        logger.warn("Not global platform OID");
//                    }
//                }
//
//                // Lifecycle
//                BerTlv lc = prop.find(new BerTag(0x9F, 0x6E));
//                if (lc != null) {
//                    logger.debug("Lifecycle data (ignored): " + HexUtils.bin2hex(lc.getBytesValue()));
//                }
//                // Max block size
//                BerTlv maxbs = prop.find(new BerTag(0x9F, 0x65));
//                if (maxbs != null) {
//                    setBlockSize(maxbs.getBytesValue());
//                }
//            } else {
//                logger.warn("No mandatory proprietary info present in FCI");
//            }
//        } else {
//            logger.warn("No FCI returned to SELECT");
//        }
//    }
//
//    private void setBlockSize(byte[] blocksize) {
//        int bs = new BigInteger(1, blocksize).intValue();
//        if (bs > this.blockSize) {
//            logger.warn("Ignoring auto-detected block size that exceeds set maximum: " + bs);
//        } else {
//            this.blockSize = bs;
//            logger.debug("Auto-detected block size: " + blockSize);
//        }
//    }
//
//    List<GPKey> getKeyInfoTemplate() throws CardException, GPException {
//        List<GPKey> result = new ArrayList<>();
//        result.addAll(GPData.get_key_template_list(GPData.fetchKeyInfoTemplate(this)));
//        return result;
//    }


    /**
     * Establishes a secure channel to the security domain.
     */
    public void openSecureChannel(GPSessionKeyProvider keys, int scpVersion, EnumSet<pro.javacard.gp.GlobalPlatform.APDUMode> securityLevel)
            throws CardException, GPException {


//        // ENC requires MAC
//        if (securityLevel.contains(APDUMode.ENC)) {
//            securityLevel.add(APDUMode.MAC);
//        }
//
//
//


//        // Calculate session keys
//        keys.calculate(scpMajorVersion, diversification_data, host_challenge, card_challenge, seq);
//
//        // Verify card cryptogram
//        byte[] my_card_cryptogram = null;
//        byte[] cntx = GPUtils.concatenate(host_challenge, card_challenge);
//            my_card_cryptogram = GPCrypto.scp03_kdf(keys.getKeyFor(GPSessionKeyProvider.KeyPurpose.MAC), (byte) 0x00, cntx, 64);
//
//        // This is the main check for possible successful authentication.
//        if (!Arrays.equals(card_cryptogram, my_card_cryptogram)) {
//            if (System.console() != null) {
//                // FIXME: this should be possible from GPTool
//                System.err.println("Read more from https://github.com/martinpaljak/GlobalPlatformPro/wiki/Keys");
//            }
//            giveStrictWarning("Card cryptogram invalid!\nCard: " + HexUtils.bin2hex(card_cryptogram) + "\nHost: " + HexUtils.bin2hex(my_card_cryptogram) + "\n!!! DO NOT RE-TRY THE SAME COMMAND/KEYS OR YOU MAY BRICK YOUR CARD !!!");
//        } else {
//            logger.debug("Verified card cryptogram: " + HexUtils.bin2hex(my_card_cryptogram));
//        }
//
//        // Calculate host cryptogram and initialize SCP wrapper
//        byte[] host_cryptogram = null;


//            host_cryptogram = GPCrypto.scp03_kdf(keys.getKeyFor(GPSessionKeyProvider.KeyPurpose.MAC), (byte) 0x01, cntx, 64);
//            wrapper = new SCP03Wrapper(keys, scpVersion, EnumSet.of(APDUMode.MAC), null, null, blockSize);
//
//        logger.debug("Calculated host cryptogram: " + HexUtils.bin2hex(host_cryptogram));
//        int P1 = APDUMode.getSetValue(securityLevel);
//        CommandAPDU externalAuthenticate = new CommandAPDU(CLA_MAC, ISO7816.INS_EXTERNAL_AUTHENTICATE_82, P1, 0, host_cryptogram);
//        response = transmit(externalAuthenticate);
//        GPException.check(response, "External authenticate failed");
//
//        // Store reference for commands
//        sessionKeys = keys;
//        wrapper.setSecurityLevel(securityLevel);

    }

    private byte[] generateHostChallenge() {
        byte[] host_challenge = new byte[8];

        gpCrypto.generate(host_challenge);
        LOGGER.trace("Generated host challenge: " + HexUtils.bin2hex(host_challenge));

        return host_challenge;
    }

    public CommandAPDU getInitializeUpdateApdu() {

        hostChallenge = generateHostChallenge();

        return new CommandAPDU(CLA_GP, INS_INITIALIZE_UPDATE, 1, 0, hostChallenge);
    }

    public void handleInitializeUpdateResponseApdu(InitializeUpdateResponseApdu initializeUpdateResponseApdu) throws GPException {

        if (initializeUpdateResponseApdu.getTotalBytes() != 32) {
            throw new GPException("Invalid INITIALIZE UPDATE response length: " + initializeUpdateResponseApdu.getTotalBytes());
        }
    }

//    // FIXME: remove the withCheck parameter, as always true?
//    private byte[] encodeKey(GPKey key, GPKey dek, boolean withCheck) {
//        try {
//            ByteArrayOutputStream baos = new ByteArrayOutputStream();
//            if (key.getType() == Type.DES3) {
//                // Encrypt key with DEK
//                Cipher cipher;
//                cipher = Cipher.getInstance(GPCrypto.DES3_ECB_CIPHER);
//                cipher.init(Cipher.ENCRYPT_MODE, dek.getKeyAs(Type.DES3));
//                byte[] cgram = cipher.doFinal(key.getBytes(), 0, 16);
//                baos.write(0x80); // 3DES
//                baos.write(cgram.length); // Length
//                baos.write(cgram);
//                if (withCheck) {
//                    byte[] kcv = GPCrypto.kcv_3des(key);
//                    baos.write(kcv.length);
//                    baos.write(kcv);
//                } else {
//                    baos.write(0);
//                }
//            } else if (key.getType() == Type.AES) {
//                //	baos.write(0xFF);
//                byte[] cgram = GPCrypto.scp03_encrypt_key(dek, key);
//                byte[] check = GPCrypto.scp03_key_check_value(key);
//                baos.write(0x88); // AES
//                baos.write(cgram.length + 1);
//                baos.write(key.getLength());
//                baos.write(cgram);
//                baos.write(check.length);
//                baos.write(check);
//            } else {
//                throw new IllegalArgumentException("Don't know how to handle " + key.getType());
//            }
//            return baos.toByteArray();
//        } catch (IOException | GeneralSecurityException e) {
//            throw new RuntimeException(e);
//        }
//    }
//
//    public void putKeys(List<GPKey> keys, boolean replace) throws GPException, CardException {
//        // Check for sanity and usability
//        if (keys.size() < 1 || keys.size() > 3) {
//            throw new IllegalArgumentException("Can add 1 or up to 3 keys at a time");
//        }
//        if (keys.size() > 1) {
//            for (int i = 1; i < keys.size(); i++) {
//                if (keys.get(i - 1).getID() != keys.get(i).getID() - 1) {
//                    throw new IllegalArgumentException("Key ID-s of multiple keys must be sequential!");
//                }
//            }
//        }
//
//        // Log and trace
//        logger.debug("PUT KEY version {}", keys.get(0).getVersion());
//        for (GPKey k : keys) {
//            logger.trace("PUT KEY:" + k);
//        }
//        // Check consistency, if template is available.
//        List<GPKey> tmpl = getKeyInfoTemplate();
//
//        if (tmpl.size() > 0) {
////            // TODO: move to GPTool
////            if ((tmpl.get(0).getVersion() < 1 || tmpl.get(0).getVersion() > 0x7F) && replace) {
////                giveStrictWarning("Trying to replace factory keys, when you need to add new ones? Is this a virgin card? (use --virgin)");
////            }
////
////            // Check if key types and lengths are the same when replacing
////            if (replace && (keys.get(0).getType() != tmpl.get(0).getType() || keys.get(0).getLength() != tmpl.get(0).getLength())) {
////                // FIXME: SCE60 template has 3DES keys but uses AES.
////                giveStrictWarning("Can not replace keys of different type or size: " + tmpl.get(0).getType() + "->" + keys.get(0).getType());
////            }
////
////            // Check for matching version numbers if replacing and vice versa
////            if (!replace && (keys.get(0).getVersion() == tmpl.get(0).getVersion())) {
////                throw new IllegalArgumentException("Not adding keys and version matches existing?");
////            }
////
////            if (replace && (keys.get(0).getVersion() != tmpl.get(0).getVersion())) {
////                throw new IllegalArgumentException("Replacing keys and versions don't match existing?");
////            }
//        } else {
//            if (replace) {
//                logger.warn("No key template on card but trying to replace. Implying add");
//                replace = false;
//            }
//        }
//
//        // Construct APDU
//        int P1 = 0x00; // New key in single command unless replace
//        if (replace) {
//            P1 = keys.get(0).getVersion();
//        }
//        int P2 = keys.get(0).getID();
//        if (keys.size() > 1) {
//            P2 |= 0x80;
//        }
//        ByteArrayOutputStream bo = new ByteArrayOutputStream();
//        try {
//            // New key version
//            bo.write(keys.get(0).getVersion());
//            // Key data
//            for (GPKey k : keys) {
//                bo.write(encodeKey(k, sessionKeys.getKeyFor(GPSessionKeyProvider.KeyPurpose.DEK), true));
//            }
//        } catch (IOException e) {
//            throw new RuntimeException(e);
//        }
//
//        CommandAPDU command = new CommandAPDU(CLA_GP, INS_PUT_KEY, P1, P2, bo.toByteArray());
//        ResponseAPDU response = transmit(command);
//        GPException.check(response, "PUT KEY failed");
//    }
//
//    // Puts a RSA public key for DAP purposes (format 1)
//    public void putKey(RSAPublicKey pubkey, int version) throws CardException, GPException {
//        ByteArrayOutputStream bo = new ByteArrayOutputStream();
//
//        try {
//            bo.write(version); // DAP key Version number
//            bo.write(0xA1); // Modulus
//            byte[] modulus = GPUtils.positive(pubkey.getModulus());
//            byte[] exponent = GPUtils.positive(pubkey.getPublicExponent());
//            bo.write(modulus.length);
//            bo.write(modulus);
//            bo.write(0xA0);
//            bo.write(exponent.length);
//            bo.write(exponent);
//            bo.write(0x00); // No KCV
//        } catch (IOException e) {
//            throw new RuntimeException(e);
//        }
//
//        CommandAPDU command = new CommandAPDU(CLA_GP, INS_PUT_KEY, 0x00, 0x01, bo.toByteArray());
//        ResponseAPDU response = transmit(command);
//        GPException.check(response, "PUT KEY failed");
//    }

//    // TODO: The way registry parsing mode is piggybacked to the registry class is not really nice.
//    private byte[] getConcatenatedStatus(GPRegistry reg, int p1, byte[] data) throws CardException, GPException {
//        // By default use tags
//        int p2 = reg.tags ? 0x02 : 0x00;
//
//        CommandAPDU cmd = new CommandAPDU(CLA_GP, INS_GET_STATUS, p1, p2, data, 256);
//        ResponseAPDU response = transmit(cmd);
//
//        // Workaround for legacy cards, like SCE 6.0 FIXME: this does not work properly
//        // Find a different way to adjust the response parser without touching the overall spec mode
//
//        // If ISD-s are asked and none is returned, it could be either
//        // - SSD
//        // - no support for tags
//        if (p1 == 0x80 && response.getSW() == 0x6A86) {
//            if (p2 == 0x02) {
//                // If no support for tags. Re-issue command without requesting tags
//                reg.tags = false;
//                return getConcatenatedStatus(reg, p1, data);
//            }
//        }
//
//        int sw = response.getSW();
//        if ((sw != ISO7816.SW_NO_ERROR) && (sw != 0x6310)) {
//            // Possible values:
//            if (sw == 0x6A88) {
//                // No data to report
//                return response.getData();
//
//            }
//            // 0x6A86 - no tags support or ISD asked from SSD
//            // 0a6A81 - Same as 6A88 ?
//            logger.warn("GET STATUS failed for " + HexUtils.bin2hex(cmd.getBytes()) + " with " + GPData.sw2str(response.getSW()));
//            return response.getData();
//        }
//
//        ByteArrayOutputStream bo = new ByteArrayOutputStream();
//        try {
//            bo.write(response.getData());
//            while (response.getSW() == 0x6310 && response.getData().length > 0) {
//                cmd = new CommandAPDU(CLA_GP, INS_GET_STATUS, p1, p2 | 0x01, data, 256);
//                response = transmit(cmd);
//                GPException.check(response, "GET STATUS failed for " + HexUtils.bin2hex(cmd.getBytes()), 0x6310);
//                bo.write(response.getData());
//            }
//        } catch (IOException e) {
//            throw new RuntimeException(e);
//        }
//        return bo.toByteArray();
//    }
//
//    public enum APDUMode {
//        // bit values as expected by EXTERNAL AUTHENTICATE
//        CLR(0x00), MAC(0x01), ENC(0x02), RMAC(0x10), RENC(0x20);
//
//        private final int value;
//
//        APDUMode(int value) {
//            this.value = value;
//        }
//
//        public static int getSetValue(EnumSet<APDUMode> s) {
//            int v = 0;
//            for (APDUMode m : s) {
//                v |= m.value;
//            }
//            return v;
//        }
//
//        public static APDUMode fromString(String s) {
//            return valueOf(s.trim().toUpperCase());
//        }
//    }
//
//
//    public enum GPSpec {OP201, GP211, GP22}
//
}

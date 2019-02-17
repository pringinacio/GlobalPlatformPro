package pro.javacard.gp.profiledownload;

public class InitializeUpdateResponseApdu {
    private int totalBytes;
    private byte[] diversificationData;
    // The three bytes of key information, each corresponds to : scpKeyVersion, scpMajorVersion and scp_i
    private int scpKeyVersion;
    private int scpMajorVersion;
    private int scpI;
    private byte[] cardChallenge;
    private byte[] cardCryptogram;
    private byte[] sequenceCounter;

    public byte[] getSequenceCounter() {
        return sequenceCounter;
    }

    public void setSequenceCounter(byte[] sequenceCounter) {
        this.sequenceCounter = sequenceCounter;
    }

    public int getTotalBytes() {
        return totalBytes;
    }

    public void setTotalBytes(int totalBytes) {
        this.totalBytes = totalBytes;
    }

    public byte[] getDiversificationData() {
        return diversificationData;
    }

    public void setDiversificationData(byte[] diversificationData) {
        this.diversificationData = diversificationData;
    }

    public int getScpKeyVersion() {
        return scpKeyVersion;
    }

    public void setScpKeyVersion(int scpKeyVersion) {
        this.scpKeyVersion = scpKeyVersion;
    }

    public int getScpMajorVersion() {
        return scpMajorVersion;
    }

    public void setScpMajorVersion(int scpMajorVersion) {
        this.scpMajorVersion = scpMajorVersion;
    }

    public int getScpI() {
        return scpI;
    }

    public void setScpI(int scpI) {
        this.scpI = scpI;
    }

    public byte[] getCardChallenge() {
        return cardChallenge;
    }

    public void setCardChallenge(byte[] cardChallenge) {
        this.cardChallenge = cardChallenge;
    }

    public byte[] getCardCryptogram() {
        return cardCryptogram;
    }

    public void setCardCryptogram(byte[] cardCryptogram) {
        this.cardCryptogram = cardCryptogram;
    }
}

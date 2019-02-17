package pro.javacard.gp.profiledownload;

import pro.javacard.gp.host.HostDownloadProfile;

import javax.smartcardio.CommandAPDU;

public class ProfileDownloadLogic {

    public static void main(String[] args) throws Exception{
        HostDownloadProfile hostDownloadProfile = new HostDownloadProfile();
        CommandAPDU commandAPDU = hostDownloadProfile.getInitializeUpdateApdu();

        InitializeUpdateResponseApdu initializeUpdateResponseApdu = null;
        hostDownloadProfile.handleInitializeUpdateResponseApdu(initializeUpdateResponseApdu);

    }
}

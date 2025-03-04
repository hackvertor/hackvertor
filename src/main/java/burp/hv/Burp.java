package burp.hv;

import burp.api.montoya.core.Version;

public class Burp {
    public enum Capability {
        REGISTER_HOTKEY(20250200000036948L);

        private final long minimumSupportedBuildNumber;

        Capability(long minimumSupportedBuildNumber) {
            this.minimumSupportedBuildNumber = minimumSupportedBuildNumber;
        }
    }

    private final Version version;

    public Burp(Version version) {
        this.version = version;
    }

    public boolean hasCapability(Capability capability) {
        return version.buildNumber() >= capability.minimumSupportedBuildNumber;
    }
}
package burp.hv;

import burp.api.montoya.core.Version;

public class Burp {
    public enum Capability {
        REGISTER_HOTKEY(20250300000037651L),
        REGISTER_HOTKEY_WITH_NAME(20251100000043160L),
        REGISTER_HOTKEY_IN_TABLE(20251202000043958L),
        REGISTER_HOTKEY_IN_ALL_CONTEXTS(20251202000043958L);
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
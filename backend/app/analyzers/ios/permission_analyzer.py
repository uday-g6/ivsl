from app.analyzers.ios.base import BaseAnalyzer, AnalyzerContext, RawFinding


# Mapping of usage description keys to display names
PERMISSION_MAP = {
    "NSCameraUsageDescription": "Camera",
    "NSMicrophoneUsageDescription": "Microphone",
    "NSPhotoLibraryUsageDescription": "Photo Library (read)",
    "NSPhotoLibraryAddUsageDescription": "Photo Library (write)",
    "NSLocationWhenInUseUsageDescription": "Location (when in use)",
    "NSLocationAlwaysAndWhenInUseUsageDescription": "Location (always)",
    "NSLocationAlwaysUsageDescription": "Location (always, deprecated)",
    "NSContactsUsageDescription": "Contacts",
    "NSCalendarsUsageDescription": "Calendar",
    "NSRemindersUsageDescription": "Reminders",
    "NSBluetoothAlwaysUsageDescription": "Bluetooth (always)",
    "NSBluetoothPeripheralUsageDescription": "Bluetooth Peripheral (deprecated)",
    "NSLocalNetworkUsageDescription": "Local Network",
    "NSSpeechRecognitionUsageDescription": "Speech Recognition",
    "NSMotionUsageDescription": "Motion & Fitness",
    "NSFaceIDUsageDescription": "Face ID",
    "NSUserTrackingUsageDescription": "Tracking",
    "NSHealthShareUsageDescription": "Health (read)",
    "NSHealthUpdateUsageDescription": "Health (write)",
    "NSAppleMusicUsageDescription": "Apple Music",
    "NSHealthClinicalHealthRecordsShareUsageDescription": "Health Clinical Records",
    "NSBluetoothAlwaysUsageDescription": "Bluetooth Always",
    "NSNearbyInteractionUsageDescription": "Nearby Interaction",
    "NSFallDetectionUsageDescription": "Fall Detection",
    "NSSensorKitUsageDescription": "SensorKit",
}

# Sensitive permissions — usage description MUST be present if used
SENSITIVE_PERMS = {
    "NSCameraUsageDescription": "camera",
    "NSMicrophoneUsageDescription": "microphone",
    "NSPhotoLibraryUsageDescription": "photo",
    "NSLocationWhenInUseUsageDescription": "location",
    "NSLocationAlwaysUsageDescription": "location",
    "NSContactsUsageDescription": "contact",
    "NSBluetoothAlwaysUsageDescription": "bluetooth",
    "NSFaceIDUsageDescription": "faceid",
    "NSHealthShareUsageDescription": "health",
    "NSUserTrackingUsageDescription": "tracking",
}

# Background modes — required justification
VALID_BG_MODES = {
    "audio": "audio",
    "location": "location",
    "voip": "voip",
    "fetch": "fetch",
    "remote-notification": "remote-notification",
    "processing": "processing",
    "bluetooth-central": "bluetooth-central",
    "bluetooth-peripheral": "bluetooth-peripheral",
    "external-accessory": "external-accessory",
    "nearby-interaction": "nearby-interaction",
}


class PermissionAnalyzer(BaseAnalyzer):
    name = "permissions"

    def run(self, ctx: AnalyzerContext):
        findings = []
        self.result = {"declared": [], "missing": [], "background_modes": []}
        plist = ctx.info_plist or {}

        # 1. Declared permissions
        for key, name in PERMISSION_MAP.items():
            if key in plist:
                desc = plist[key]
                self.result["declared"].append({"key": key, "name": name, "description": desc})
                # Check if description is meaningful
                if isinstance(desc, str) and len(desc.strip()) < 10:
                    findings.append(RawFinding(
                        rule_id="PERMISSION_DESC_TOO_SHORT",
                        analyzer=self.name, category="Permissions",
                        severity="medium", confidence="high",
                        title=f"Permission description too vague: {name}",
                        description=f"{key} is set but the description is too short ({len(desc)} chars). App Store may reject.",
                        evidence=f"{key}: '{desc}'",
                        remediation=f"Provide a clear, specific usage description for {name}.",
                    ))

        # 2. Background modes
        bg_modes = plist.get("UIBackgroundModes", []) or []
        for mode in bg_modes:
            self.result["background_modes"].append(mode)
            if mode not in VALID_BG_MODES:
                findings.append(RawFinding(
                    rule_id="PERMISSION_UNUSUAL_BG_MODE",
                    analyzer=self.name, category="Permissions",
                    severity="low", confidence="medium",
                    title=f"Unusual background mode: {mode}",
                    description="Background mode may not be properly justified. App Store may question this.",
                    evidence=mode,
                    remediation=f"Remove UIBackgroundModes '{mode}' if not essential.",
                ))
            elif mode in ("location", "voip", "audio"):
                findings.append(RawFinding(
                    rule_id="PERMISSION_SENSITIVE_BG_MODE",
                    analyzer=self.name, category="Permissions",
                    severity="info", confidence="high",
                    title=f"Sensitive background mode enabled: {mode}",
                    description=f"App runs in background for {mode}. Ensure proper justification.",
                    evidence=mode,
                    remediation="Document why this background mode is required for App Store review.",
                ))

        # 3. Check for missing usage descriptions
        # Look for permission-implying APIs in the binary
        # Instead, check if binary uses certain frameworks
        frameworks = []
        fw_dir = ctx.app_root / "Frameworks"
        if fw_dir.exists():
            frameworks = [f.name.lower() for f in fw_dir.iterdir() if f.is_dir()]

        # Heuristic: if app uses AVCapture, need camera permission
        binary_path = ctx.executable_path
        if binary_path and binary_path.exists():
            try:
                binary_bytes = binary_path.read_bytes()[:5_000_000]
                binary_text = binary_bytes.decode("utf-8", errors="ignore").lower()

                # Check each sensitive permission
                framework_indicators = {
                    "NSCameraUsageDescription": ["avcapture", "avfoundation"],
                    "NSMicrophoneUsageDescription": ["avaudiosession", "coreaudio"],
                    "NSPhotoLibraryUsageDescription": ["phphotolibrary", "uiimagepicker"],
                    "NSLocationWhenInUseUsageDescription": ["cllocationmanager", "corelocation"],
                    "NSContactsUsageDescription": ["cncontactstore", "addressbook"],
                    "NSFaceIDUsageDescription": ["lacontext", "localauthentication"],
                    "NSHealthShareUsageDescription": ["hkhealthstore", "healthkit"],
                }

                for key, indicators in framework_indicators.items():
                    if key in plist:
                        continue  # Already declared
                    for indicator in indicators:
                        if indicator in binary_text:
                            name = PERMISSION_MAP.get(key, key)
                            self.result["missing"].append({"key": key, "name": name})
                            findings.append(RawFinding(
                                rule_id="PERMISSION_MISSING_USAGE",
                                analyzer=self.name, category="Permissions",
                                severity="high", confidence="medium",
                                title=f"Missing usage description for {name}",
                                description=f"App uses {indicator} API but {key} is not declared in Info.plist. App Store will reject this.",
                                evidence=f"Found '{indicator}' in binary, but '{key}' is missing from Info.plist",
                                impact="App Store submission will fail.",
                                remediation=f"Add {key} to Info.plist with a clear description of why {name} access is needed.",
                            ))
                            break
            except Exception:
                pass

        return findings

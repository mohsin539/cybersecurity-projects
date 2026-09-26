package com.mdmlite.agent;

import android.app.KeyguardManager;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.net.ConnectivityManager;
import android.net.NetworkCapabilities;
import android.os.Build;
import android.os.Environment;
import android.os.SystemClock;
import android.provider.Settings;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/** Collects device telemetry in the same JSON shape used by the desktop checker. */
public final class TelemetryCollector {

    public static final String AGENT_VERSION = "1.0.0";

    private final Context ctx;

    public TelemetryCollector(Context ctx) {
        this.ctx = ctx.getApplicationContext();
    }

    public JSONObject collect() throws JSONException {
        JSONObject t = new JSONObject();
        t.put("os", collectOs());
        t.put("hardware", collectHardware());
        t.put("apps", collectApps());
        t.put("security", collectSecurity());
        t.put("network", collectNetwork());
        t.put("agent", new JSONObject()
                .put("version", AGENT_VERSION)
                .put("uptime_sec", SystemClock.elapsedRealtime() / 1000L));
        return t;
    }

    private JSONObject collectOs() throws JSONException {
        return new JSONObject()
                .put("version", Build.VERSION.RELEASE)
                .put("sdk", Build.VERSION.SDK_INT)
                .put("build", Build.VERSION.INCREMENTAL + " (" + Build.DISPLAY + ")");
    }

    private JSONObject collectHardware() throws JSONException {
        return new JSONObject()
                .put("brand", Build.BRAND)
                .put("model", Build.MODEL)
                .put("manufacturer", Build.MANUFACTURER)
                .put("serial", Build.SERIAL);
    }

    private JSONObject collectApps() {
        JSONArray installed = new JSONArray();
        try {
            PackageManager pm = ctx.getPackageManager();
            List<PackageInfo> pkgs;
            if (Build.VERSION.SDK_INT >= 33) {
                pkgs = pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(0));
            } else {
                //noinspection deprecation
                pkgs = pm.getInstalledPackages(0);
            }
            for (PackageInfo pi : pkgs) {
                installed.put(pi.packageName);
            }
        } catch (Throwable ignore) {
            // QUERY_ALL_PACKAGES denied or OEM restriction: report what we have
        }
        JSONObject apps = new JSONObject();
        try {
            apps.put("installed", installed);
        } catch (JSONException ignore) {
        }
        return apps;
    }

    private JSONObject collectSecurity() throws JSONException {
        boolean rooted = isRooted();
        boolean unknownsources = isUnknownSourcesEnabled();
        boolean sideLoading = unknownsources;
        boolean screenLock = isScreenLockSecure();
        boolean encryption = isEncryptionActive();
        boolean playProtect = isPlayServicesPresent();
        boolean biometric = isBiometricUsable();

        return new JSONObject()
                .put("rooted", rooted)
                .put("jailbreak", rooted)
                .put("unknown_sources", unknownsources)
                .put("side_loading", sideLoading)
                .put("screen_lock", screenLock)
                .put("encryption", encryption)
                .put("play_protect", playProtect)
                .put("biometric", biometric)
                .put("verifier_status", verifierStatus());
    }

    private JSONObject collectNetwork() throws JSONException {
        boolean vpn = false;
        try {
            ConnectivityManager cm = (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
            NetworkCapabilities nc = cm.getNetworkCapabilities(cm.getActiveNetwork());
            vpn = nc != null && nc.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
        } catch (Throwable ignore) {
        }
        return new JSONObject()
                .put("vpn", vpn)
                .put("geofenced", true);
    }

    private boolean isRooted() {
        String[] suPaths = {
                "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su",
                "/system/app/Superuser.apk", "/data/local/xbin/su", "/data/local/bin/su"
        };
        for (String p : suPaths) {
            if (new File(p).exists()) return true;
        }
        String tags = Build.TAGS;
        return tags != null && tags.contains("test-keys");
    }

    private boolean isUnknownSourcesEnabled() {
        try {
            // Install unknown apps is per-app since API 26; this is the best global proxy.
            int verifier = Settings.Global.getInt(
                    ctx.getContentResolver(), "verifier_verify_adb_installs", 1);
            if (verifier == 0) return true;
            int legacy = Settings.Secure.getInt(
                    ctx.getContentResolver(), "install_non_market_apps", 0);
            return legacy == 1;
        } catch (Throwable ignore) {
            return false;
        }
    }

    private boolean isScreenLockSecure() {
        try {
            KeyguardManager km = (KeyguardManager) ctx.getSystemService(Context.KEYGUARD_SERVICE);
            return km != null && km.isKeyguardSecure();
        } catch (Throwable ignore) {
            return false;
        }
    }

    private boolean isEncryptionActive() {
        try {
            android.app.admin.DevicePolicyManager dpm =
                    (android.app.admin.DevicePolicyManager) ctx.getSystemService(Context.DEVICE_POLICY_SERVICE);
            int status = dpm.getStorageEncryptionStatus();
            return status == android.app.admin.DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE
                    || status == android.app.admin.DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY;
        } catch (Throwable ignore) {
            // Some OEMs throw; fall back to emulated storage heuristic.
            return !Environment.isExternalStorageEmulated();
        }
    }

    private boolean isPlayServicesPresent() {
        try {
            ctx.getPackageManager().getPackageInfo("com.google.android.gms", 0);
            return true;
        } catch (Throwable ignore) {
            return false;
        }
    }

    private boolean isBiometricUsable() {
        try {
            if (Build.VERSION.SDK_INT >= 23) {
                FingerprintManager fm = (FingerprintManager) ctx.getSystemService(Context.FINGERPRINT_SERVICE);
                if (fm != null && fm.isHardwareDetected()) return true;
            }
            KeyguardManager km = (KeyguardManager) ctx.getSystemService(Context.KEYGUARD_SERVICE);
            return km != null && km.isKeyguardSecure();
        } catch (Throwable ignore) {
            return false;
        }
    }

    private String verifierStatus() {
        try {
            int v = Settings.Global.getInt(ctx.getContentResolver(), "verifier_verify_adb_installs", 1);
            return v == 1 ? "ENABLED" : "DISABLED";
        } catch (Throwable ignore) {
            return "UNKNOWN";
        }
    }
}
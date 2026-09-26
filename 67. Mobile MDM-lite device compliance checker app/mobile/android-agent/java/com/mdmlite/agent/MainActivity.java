package com.mdmlite.agent;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

/** MDM-Lite on-device agent: collect -> evaluate -> report to desktop checker. */
public class MainActivity extends Activity {

    private final Handler ui = new Handler(Looper.getMainLooper());
    private TextView statusView;
    private TextView summaryView;
    private LinearLayout rulesBox;
    private TextView telemetryView;
    private EditText serverInput;
    private JSONObject lastResult;
    private JSONObject lastTelemetry;

    private static final String PREFS = "mdmlite_agent";
    private static final String KEY_URL = "server_url";
    private static final String DEFAULT_URL = "http://10.0.2.2:8791/api/devices"; // emulator default

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        buildUi();
        String saved = getSharedPreferences(PREFS, MODE_PRIVATE).getString(KEY_URL, DEFAULT_URL);
        serverInput.setText(saved);
        scan();
    }

    // ------------------------------------------------------------------ actions
    private void scan() {
        statusView.setText("Collecting telemetry…");
        statusView.setTextColor(0xFFF59E0B);
        rulesBox.removeAllViews();
        try {
            TelemetryCollector collector = new TelemetryCollector(this);
            lastTelemetry = collector.collect();
            lastResult = ComplianceEngine.evaluate(lastTelemetry);
            renderResult(lastResult);
            telemetryView.setText(prettify(lastTelemetry));
        } catch (Exception e) {
            statusView.setText("Error: " + e.getMessage());
            statusView.setTextColor(0xFFEF4444);
            telemetryView.setText(e.toString());
        }
    }

    private void renderResult(JSONObject r) throws Exception {
        String st = r.getString("status");
        boolean ok = "COMPLIANT".equals(st);
        statusView.setText(st.replace('_', ' ')
                + "   ·   score " + r.optDouble("score", 0) + "%");
        statusView.setTextColor(ok ? 0xFF22C55E : 0xFFEF4444);
        summaryView.setText("pass " + r.getInt("pass_count")
                + "  /  fail " + r.getInt("fail_count")
                + "  /  n/a " + r.getInt("na_count")
                + "   ·   threshold " + r.optDouble("threshold", 80) + "%");

        rulesBox.removeAllViews();
        JSONArray results = r.optJSONArray("results");
        for (int i = 0; i < results.length(); i++) {
            JSONObject rule = results.getJSONObject(i);
            rulesBox.addView(ruleRow(rule));
        }
    }

    private View ruleRow(JSONObject rule) throws Exception {
        String verdict = rule.getString("verdict");
        int color;
        String label;
        if ("PASS".equals(verdict)) { color = 0xFF22C55E; label = "PASS"; }
        else if ("FAIL".equals(verdict)) { color = 0xFFEF4444; label = "FAIL"; }
        else { color = 0xFF64748B; label = "N/A"; }

        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(dp(14), dp(10), dp(14), dp(10));
        LinearLayout.LayoutParams rowLp = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        rowLp.bottomMargin = dp(6);
        row.setLayoutParams(rowLp);
        row.setBackground(roundBg(0x151F37, 0xFF24334F, 10));
        row.setElevation(dp(1));

        TextView chip = new TextView(this);
        chip.setText(label);
        chip.setTextColor(0xFF0B1120);
        chip.setTypeface(Typeface.DEFAULT_BOLD);
        chip.setPadding(dp(8), dp(3), dp(8), dp(3));
        chip.setBackground(roundBg(color, color, 99));
        row.addView(chip, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT, 0f));

        TextView txt = new TextView(this);
        txt.setTextSize(12);
        txt.setTextColor(0xFFE7ECF5);
        String severity = rule.optString("severity", "?");
        txt.setText("   " + rule.getString("label") + "\n      "
                + rule.getString("rule_id") + "  ·  " + severity
                + "  ·  expected " + rule.optString("expected")
                + "  ·  actual " + rule.optString("actual"));
        row.addView(txt, new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        return row;
    }

    private void sendToChecker() {
        if (lastResult == null || lastTelemetry == null) return;
        String endpoint = serverInput.getText().toString().trim();
        if (endpoint.isEmpty()) {
            Toast.makeText(this, "Set a server URL first", Toast.LENGTH_SHORT).show();
            return;
        }
        getSharedPreferences(PREFS, MODE_PRIVATE).edit().putString(KEY_URL, endpoint).apply();
        final JSONObject payload;
        try {
            payload = new JSONObject()
                    .put("name", "Android-" + android.os.Build.MODEL)
                    .put("platform", "android")
                    .put("model", android.os.Build.MODEL)
                    .put("department", "BYOD")
                    .put("owner", android.os.Build.MODEL)
                    .put("mode", "adb")
                    .put("telemetry", lastTelemetry);
        } catch (Exception e) {
            Toast.makeText(this, "Payload build failed: " + e.getMessage(), Toast.LENGTH_SHORT).show();
            return;
        }
        Toast.makeText(this, "Sending to " + endpoint + " …", Toast.LENGTH_SHORT).show();
        new Thread(() -> {
            Sender.Result r = Sender.send(endpoint, payload, 8000);
            ui.post(() -> Toast.makeText(MainActivity.this,
                    "Upload " + (r.ok ? "OK" : "FAILED") + "\n" + r.body,
                    Toast.LENGTH_LONG).show());
        }).start();
    }

    private void copyJson() {
        if (lastResult == null) return;
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        cm.setPrimaryClip(ClipData.newPlainText("mdmlite_report", prettify(lastResult)));
        Toast.makeText(this, "JSON copied to clipboard", Toast.LENGTH_SHORT).show();
    }

    // ------------------------------------------------------------------ UI build
    private void buildUi() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(18), dp(24), dp(18), dp(24));
        root.setBackgroundColor(0xFF070B16);

        root.addView(title());
        statusView = sectionStatus();
        root.addView(statusView);
        summaryView = section();
        root.addView(summaryView);

        TextView rulesTitle = sectionTitle("Compliance rules");
        root.addView(rulesTitle);
        rulesBox = new LinearLayout(this);
        rulesBox.setOrientation(LinearLayout.VERTICAL);
        root.addView(rulesBox);

        LinearLayout btns = new LinearLayout(this);
        btns.setOrientation(LinearLayout.HORIZONTAL);
        btns.setPadding(0, dp(14), 0, dp(4));
        btns.addView(btn("Rescan", 0xFF6366F1, v -> scan()));
        btns.addView(btn("Send to checker", 0xFF2563EB, v -> sendToChecker()));
        btns.addView(btn("Copy JSON", 0xFF1E293B, v -> copyJson()));

        serverInput = new EditText(this);
        serverInput.setTextSize(12);
        serverInput.setSingleLine(true);
        serverInput.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        serverInput.setHint("Checker URL (e.g. http://192.168.1.20:8791/api/devices)");
        serverInput.setTextColor(0xFF22D3EE);

        root.addView(btns);
        root.addView(serverInput);
        root.addView(sectionTitle("Raw telemetry"));

        ScrollView scroller = new ScrollView(this);
        telemetryView = new TextView(this);
        telemetryView.setTextSize(10);
        telemetryView.setTypeface(Typeface.MONOSPACE);
        telemetryView.setTextColor(0xFF94A3B8);
        scroller.addView(telemetryView);
        root.addView(scroller, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));

        setContentView(root);
    }

    private TextView title() {
        TextView tv = new TextView(this);
        tv.setText("MDM-Lite Agent  🛡️");
        tv.setTextSize(20);
        tv.setTypeface(Typeface.DEFAULT_BOLD);
        tv.setTextColor(0xFFE7ECF5);
        tv.setGravity(Gravity.CENTER);
        tv.setPadding(0, 0, 0, dp(14));
        return tv;
    }

    private TextView sectionTitle(String text) {
        TextView tv = new TextView(this);
        tv.setText(text);
        tv.setTextSize(11);
        tv.setTypeface(Typeface.DEFAULT_BOLD);
        tv.setTextColor(0xFF8B99B1);
        tv.setLetterSpacing(0.05f);
        tv.setPadding(0, dp(14), 0, dp(6));
        return tv;
    }

    private TextView sectionStatus() {
        TextView tv = new TextView(this);
        tv.setTextSize(24);
        tv.setTypeface(Typeface.DEFAULT_BOLD);
        tv.setPadding(0, 0, 0, dp(2));
        return tv;
    }

    private TextView section() {
        TextView tv = new TextView(this);
        tv.setTextSize(13);
        tv.setTextColor(0xFF8B99B1);
        tv.setPadding(0, 0, 0, dp(6));
        return tv;
    }

    private Button btn(String text, int color, View.OnClickListener onClick) {
        Button b = new Button(this);
        b.setText(text);
        b.setTextSize(12);
        b.setTypeface(Typeface.DEFAULT_BOLD);
        b.setTextColor(0xFFFFFFFF);
        b.setAllCaps(false);
        b.setBackground(roundBg(color, 0x00000000, 12));
        b.setPadding(dp(10), 0, dp(10), 0);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0,
                dp(46), 1f);
        lp.setMargins(0, 0, dp(8), 0);
        b.setLayoutParams(lp);
        b.setOnClickListener(onClick);
        return b;
    }

    private GradientDrawable roundBg(int fill, int stroke, int radius) {
        GradientDrawable d = new GradientDrawable();
        d.setColor(fill);
        d.setCornerRadius(dp(radius));
        if (stroke != 0) d.setStroke(dp(1), stroke);
        return d;
    }

    private int dp(int v) {
        return Math.round(getResources().getDisplayMetrics().density * v);
    }

    private static String prettify(JSONObject o) {
        try {
            return o.toString(2);
        } catch (Exception e) {
            return o.toString();
        }
    }
}
import SwiftUI

@main
struct MDMLiteAgentApp: App {
    var body: some Scene {
        WindowGroup {
            AgentView()
        }
    }
}

/// Minimal iOS agent UI: collect + evaluate + show verdict + share report.
struct AgentView: View {
    @State private var result: [String: Any]?
    @State private var telemetry: [String: Any]?
    @State private var running = false
    @State private var checkerURL = "http://192.168.1.20:8791/api/devices"
    @State private var statusText = "Tap Collect to begin."

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    statusCard
                    if let result = result { resultList(result) }
                    actionRow
                    TextField("Checker URL", text: $checkerURL)
                        .textFieldStyle(.roundedBorder)
                        .autocapitalization(.none)
                        .keyboardType(.URL)
                    Text(prettify(telemetry))
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundColor(.secondary)
                }
                .padding()
                .navigationTitle("MDM-Lite Agent")
            }
        }
    }

    private var statusCard: some View {
        VStack(alignment: .leading, spacing: 6) {
            if let result = result {
                let status = result["status"] as? String ?? "PENDING"
                Text(status.replacingOccurrences(of: "_", with: " "))
                    .font(.largeTitle.bold())
                    .foregroundColor(status == "COMPLIANT" ? .green : .red)
                Text("score \(result["score"] ?? 0)%  ·  pass \(result["pass_count"] ?? 0) / fail \(result["fail_count"] ?? 0)")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
            } else {
                Text(statusText).font(.title3.bold())
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(Color(.secondarySystemBackground))
        .cornerRadius(14)
    }

    private func resultList(_ result: [String: Any]) -> some View {
        let rows = result["results"] as? [[String: Any]] ?? []
        return ForEach(rows.indices, id: \.self) { i in
            let row = rows[i]
            HStack {
                Text(row["verdict"] as? String ?? "")
                    .font(.caption.bold()).padding(6)
                    .foregroundColor(.white)
                    .background(row["verdict"] as? String == "PASS" ? Color.green : Color.red)
                    .cornerRadius(6)
                VStack(alignment: .leading, spacing: 2) {
                    Text(row["label"] as? String ?? "").font(.subheadline)
                    Text("\(row["rule_id"] ?? "") · \(row["severity"] ?? "")")
                        .font(.caption2).foregroundColor(.secondary)
                }
                Spacer()
            }
            .padding(8)
            .background(Color(.secondarySystemBackground))
            .cornerRadius(10)
        }
    }

    private var actionRow: some View {
        HStack {
            Button {
                run()
            } label: {
                Label(running ? "Collecting…" : "Collect & Evaluate",
                      systemImage: "arrow.clockwise")
            }
            .disabled(running)
            .buttonStyle(.borderedProminent)

            Button {
                let payload = payload()
                Task { await send(payload) }
            } label: {
                Label("Send to checker", systemImage: "paperplane")
            }
            .buttonStyle(.bordered)

            ShareLink(item: prettify(result) ?? "") {
                Label("Share", systemImage: "square.and.arrow.up")
            }
        }
    }

    private func run() {
        running = true
        statusText = "Collecting telemetry…"
        DispatchQueue.global().async {
            let collector = TelemetryCollector()
            let tel = collector.collect()
            let res = ComplianceEngine().evaluate(telemetry: tel)
            DispatchQueue.main.async {
                telemetry = tel
                result = res
                running = false
                statusText = "Done."
            }
        }
    }

    private func payload() -> [String: Any] {
        let model = telemetry.flatMap { $0["hardware"] as? [String: Any] }
        return [
            "name": "iOS-" + (model?["name"] as? String ?? "iPhone"),
            "platform": "ios",
            "model": model?["model"] as? String ?? "",
            "department": "BYOD",
            "owner": UIDevice.current.name,
            "mode": "telemetry",
            "telemetry": telemetry ?? [:],
        ]
    }

    private func send(_ payload: [String: Any]) {
        guard let url = URL(string: checkerURL),
              let body = try? JSONSerialization.data(withJSONObject: payload) else { return }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = body
        URLSession.shared.dataTask(with: req) { _, _, error in
            DispatchQueue.main.async {
                statusText = error == nil ? "Sent ✓ (see checker dashboard)" : "Send failed: \(error!.localizedDescription)"
            }
        }.resume()
    }

    private func prettify(_ value: Any?) -> String {
        guard let value else { return "no data" }
        return (try? JSONSerialization.data(withJSONObject: value, options: [.prettyPrinted, .sortedKeys]))
            .flatMap { String(data: $0, encoding: .utf8) } ?? String(describing: value)
    }
}
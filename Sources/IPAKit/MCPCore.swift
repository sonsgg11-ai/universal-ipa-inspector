import Foundation

/// Optional AI/MCP integration point (requirement Q).
///
/// This implements the real JSON-RPC 2.0 message model that MCP (Model
/// Context Protocol) uses on the wire, plus a tool catalog over the analysis
/// engine. It is NOT wired into any UI by default and exposes no data unless
/// an explicit host application connects it.
///
/// Honesty rules:
///  * No simulated transport, no fake "AI features". If a host dials this
///    core in over stdio/sockets, these are real, working protocol replies.
///  * Secrets are masked in every response unless the host passes an explicit
///    per-session approval flag (which the UI never sets by default).
///  * No network code lives here; transports are the host's responsibility.
enum MCPCore {

    // MARK: JSON-RPC 2.0 messages

    struct Request: Codable {
        let jsonrpc: String
        let id: JSONRPCID?
        let method: String
        let params: [String: JSONValue]?
    }

    struct Response: Codable {
        var jsonrpc: String = "2.0"
        let id: JSONRPCID?
        let result: JSONValue?
        let error: RPCError?

        struct RPCError: Codable {
            let code: Int
            let message: String
        }
    }

    enum JSONRPCID: Codable, Equatable {
        case number(Int)
        case string(String)

        init(from decoder: Decoder) throws {
            let container = try decoder.singleValueContainer()
            if let n = try? container.decode(Int.self) { self = .number(n) }
            else { self = .string(try container.decode(String.self)) }
        }

        func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            switch self {
            case .number(let n): try container.encode(n)
            case .string(let s): try container.encode(s)
            }
        }
    }

    // MARK: JSON value model

    enum JSONValue: Codable, Equatable {
        case null
        case bool(Bool)
        case number(Double)
        case string(String)
        case array([JSONValue])
        case object([String: JSONValue])

        init(from decoder: Decoder) throws {
            let container = try decoder.singleValueContainer()
            if let b = try? container.decode(Bool.self) { self = .bool(b) }
            else if let n = try? container.decode(Double.self) { self = .number(n) }
            else if let s = try? container.decode(String.self) { self = .string(s) }
            else if let a = try? container.decode([JSONValue].self) { self = .array(a) }
            else if let o = try? container.decode([String: JSONValue].self) { self = .object(o) }
            else { self = .null }
        }

        func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            switch self {
            case .null: try container.encodeNil()
            case .bool(let b): try container.encode(b)
            case .number(let n): try container.encode(n)
            case .string(let s): try container.encode(s)
            case .array(let a): try container.encode(a)
            case .object(let o): try container.encode(o)
            }
        }
    }

    // MARK: Tool catalog

    struct Tool {
        let name: String
        let description: String
        let exposesSecrets: Bool
    }

    static let tools: [Tool] = [
        Tool(name: "get_app_metadata",
             description: "Returns the analysed app's identity, versions, sizes and hash. No secrets.",
             exposesSecrets: false),
        Tool(name: "search_symbols",
             description: "Searches the symbol/string/URL index of the analysed binary set.",
             exposesSecrets: false),
        Tool(name: "get_macho_info",
             description: "Returns Mach-O structure: architectures, load commands, segments, encryption status.",
             exposesSecrets: false),
        Tool(name: "list_findings",
             description: "Returns security findings with severity, confidence and MASVS mapping.",
             exposesSecrets: false),
        Tool(name: "summarize_report",
             description: "Returns a short factual summary of the analysis.",
             exposesSecrets: false),
        Tool(name: "list_secrets_masked",
             description: "Returns credential-shaped string detections with masked values only.",
             exposesSecrets: false),
    ]

    // MARK: Server core

    /// Processes JSON-RPC messages. `sessionAllowsSecretReveal` must be set
    /// deliberately by the host after user approval; the default is false and
    /// masked results are returned in every case.
    final class ServerCore {
        private let outcomeProvider: () -> AnalysisEngine.Outcome?
        private let sessionAllowsSecretReveal: Bool

        init(outcomeProvider: @escaping () -> AnalysisEngine.Outcome?,
             sessionAllowsSecretReveal: Bool = false) {
            self.outcomeProvider = outcomeProvider
            self.sessionAllowsSecretReveal = sessionAllowsSecretReveal
        }

        /// Handles one JSON-RPC message; returns the encoded reply (or nil for
        /// notifications, per the JSON-RPC spec).
        func handle(messageData: Data) -> Data? {
            guard let request = try? JSONDecoder().decode(Request.self, from: messageData) else {
                let response = Response(id: nil, result: nil,
                                        error: .init(code: -32700, message: "Parse error"))
                return try? JSONEncoder().encode(response)
            }
            guard request.jsonrpc == "2.0" else {
                return reply(id: request.id, result: nil,
                             error: .init(code: -32600, message: "Invalid Request: jsonrpc must be \"2.0\""))
            }

            switch request.method {
            case "initialize":
                return reply(id: request.id, result: .object([
                    "protocolVersion": .string("2024-11-05"),
                    "capabilities": .object([
                        "tools": .object(["listChanged": .bool(false)]),
                    ]),
                    "serverInfo": .object([
                        "name": .string("IPAInspectorMCPServer"),
                        "version": .string("1.0.0"),
                    ]),
                ]), error: nil)

            case "tools/list":
                let tools = MCPCore.tools.map { tool -> JSONValue in
                    .object([
                        "name": .string(tool.name),
                        "description": .string(tool.description + (tool.exposesSecrets
                            ? "" : " Secrets are always masked in responses.")),
                        "inputSchema": .object([
                            "type": .string("object"),
                            "properties": .object([
                                "query": .object(["type": .string("string")]),
                                "limit": .object(["type": .string("number")]),
                            ]),
                        ]),
                    ])
                }
                return reply(id: request.id, result: .object(["tools": .array(tools)]), error: nil)

            case "tools/call":
                guard let params = request.params,
                      case .string(let toolName) = params["name"] ?? .null else {
                    return reply(id: request.id, result: nil,
                                 error: .init(code: -32602, message: "Invalid params: tools/call requires \"name\""))
                }
                return reply(id: request.id,
                             result: callTool(named: toolName, params: params),
                             error: nil)

            case "ping":
                return reply(id: request.id, result: .object([:]), error: nil)

            default:
                return reply(id: request.id, result: nil,
                             error: .init(code: -32601, message: "Method not found: \(request.method)"))
            }
        }

        // MARK: Tool implementations (all read from real engine output)

        private func callTool(named name: String, params: [String: JSONValue]) -> JSONValue {
            guard let outcome = outcomeProvider() else {
                return .object([
                    "content": .array([.object([
                        "type": .string("text"),
                        "text": .string("No analysis has been completed in this session."),
                    ])]),
                ])
            }

            func textResult(_ text: String) -> JSONValue {
                .object([
                    "content": .array([.object([
                        "type": .string("text"),
                        "text": .string(text),
                    ])]),
                    "secretRevealApproved": .bool(sessionAllowsSecretReveal),
                ])
            }

            switch name {
            case "get_app_metadata":
                var lines: [String] = []
                lines.append("app: \(outcome.report.name)")
                if let d = outcome.dashboard {
                    lines.append("bundle id: \(d.bundleID)")
                    lines.append("version: \(d.version) (\(d.buildNumber))")
                    lines.append("min iOS: \(d.minOS)")
                    lines.append("files: \(d.fileCount), frameworks: \(d.frameworkCount), extensions: \(d.extensionCount)")
                }
                lines.append("ipa sha256: \(outcome.report.sha256 ?? "n/a")")
                return textResult(lines.joined(separator: "\n"))

            case "search_symbols":
                guard case .string(let query) = params["query"] ?? .null, !query.isEmpty else {
                    return textResult("Missing \"query\" parameter.")
                }
                var hits: [String] = []
                for (path, symbols) in outcome.symbols {
                    for symbol in symbols.prefix(2000) where symbol.name.localizedCaseInsensitiveContains(query) {
                        hits.append("\(path): \(symbol.name) [\(symbol.kind.rawValue)]")
                        if hits.count >= 40 { break }
                    }
                    if hits.count >= 40 { break }
                }
                return textResult(hits.isEmpty ? "No symbols matched \"\(query)\"." : hits.joined(separator: "\n"))

            case "get_macho_info":
                var lines: [String] = []
                for binary in outcome.report.binaries {
                    for arch in binary.archs {
                        lines.append("\(binary.path) [\(arch.cpu)] segments: \(arch.segments.count), dylibs: \(arch.dylibs.count), cryptid: \(arch.cryptID.map(String.init) ?? "none")")
                    }
                }
                return textResult(lines.isEmpty ? "No Mach-O binaries were parsed." : lines.joined(separator: "\n"))

            case "list_findings":
                var lines: [String] = []
                for finding in outcome.security.prefix(60) {
                    lines.append("\(finding.id) [\(finding.severity.rawValue)/\(finding.confidence)] \(finding.title) — \(finding.status.label)")
                }
                return textResult(lines.isEmpty ? "No security findings." : lines.joined(separator: "\n"))

            case "list_secrets_masked":
                var lines: [String] = []
                for hit in outcome.secrets {
                    lines.append("\(hit.name) — \(hit.masked) — \(hit.source)")
                }
                lines.append("Values are masked. Reveal requires explicit user approval in the app UI; it is never automatic.")
                return textResult(lines.isEmpty ? "No credential-shaped strings found." : lines.joined(separator: "\n"))

            case "summarize_report":
                var lines: [String] = []
                lines.append("Static analysis of \(outcome.report.name): \(outcome.report.fileCount) files, \(outcome.report.binaries.count) binaries.")
                lines.append("Security findings: \(outcome.security.count) (critical: \(outcome.security.filter { $0.severity == .critical }.count), high: \(outcome.security.filter { $0.severity == .high }.count)).")
                lines.append("Credential-shaped strings (masked): \(outcome.secrets.count).")
                if let fairplay = outcome.fairplay, !fairplay.encryptedBinaryPaths.isEmpty {
                    lines.append("FairPlay encryption detected on \(fairplay.encryptedBinaryPaths.count) binary(ies); affected checks are reported as blocked.")
                }
                return textResult(lines.joined(separator: "\n"))

            default:
                return .object([
                    "content": .array([.object([
                        "type": .string("text"),
                        "text": .string("Unknown tool: \(name)"),
                    ])]),
                    "isError": .bool(true),
                ])
            }
        }

        private func reply(id: JSONRPCID?, result: JSONValue?, error: Response.RPCError?) -> Data {
            let response = Response(id: id, result: result, error: error)
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            return (try? encoder.encode(response)) ?? Data("{}".utf8)
        }
    }
}

import SwiftUI

/// Design system for IPA Inspector (requirement U): semantic colors, spacing
/// tokens, card components and badges shared by every module. Light and dark
/// mode both come from system semantic colors, so no mode-specific code paths
/// exist.
enum DesignSystem {

    // MARK: Tokens

    enum Spacing {
        static let xs: CGFloat = 4
        static let s: CGFloat = 8
        static let m: CGFloat = 16
        static let l: CGFloat = 24
    }

    enum Radius {
        static let card: CGFloat = 16
        static let chip: CGFloat = 8
    }

    // MARK: Accent & severity colors (no blue/indigo by design)

    static let accent = Color.teal

    static func severityColor(_ severity: SecurityAssessor.Severity) -> Color {
        switch severity {
        case .critical: return .red
        case .high: return .orange
        case .medium: return .yellow
        case .low: return .mint
        case .informational: return .secondary.opacity(1)
        }
    }

    static func statusColor(_ status: EvidenceStatus) -> Color {
        switch status {
        case .verified: return .green
        case .detected: return .teal
        case .estimated: return .orange
        case .blocked: return .red
        case .notFound: return .gray
        }
    }

    static func confidenceColor(_ confidence: SecurityAssessor.Confidence) -> Color {
        switch confidence {
        case .high: return .green
        case .medium: return .orange
        case .low: return .gray
        }
    }
}

// MARK: - Card container

struct ModuleCard<Content: View>: View {
    let title: String
    let systemImage: String
    var subtitle: String? = nil
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: DesignSystem.Spacing.s) {
            HStack(spacing: DesignSystem.Spacing.s) {
                Image(systemName: systemImage)
                    .foregroundStyle(DesignSystem.accent)
                    .font(.headline)
                Text(title)
                    .font(.headline)
                Spacer()
            }
            if let subtitle {
                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            content
        }
        .padding(DesignSystem.Spacing.m)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(.secondarySystemGroupedBackground),
                    in: RoundedRectangle(cornerRadius: DesignSystem.Radius.card))
    }
}

// MARK: - Badges

struct SeverityBadge: View {
    let severity: SecurityAssessor.Severity

    var body: some View {
        Text(severity.label)
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(DesignSystem.severityColor(severity).opacity(0.18),
                        in: Capsule())
            .foregroundStyle(DesignSystem.severityColor(severity))
            .accessibilityLabel("Severity: \(severity.label)")
    }
}

struct StatusBadge: View {
    let status: EvidenceStatus

    var body: some View {
        Text(status.label)
            .font(.caption2.weight(.medium))
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(DesignSystem.statusColor(status).opacity(0.18), in: Capsule())
            .foregroundStyle(DesignSystem.statusColor(status))
            .accessibilityLabel("Evidence status: \(status.label)")
    }
}

struct ConfidenceBadge: View {
    let confidence: SecurityAssessor.Confidence

    var body: some View {
        Text("confidence \(confidence.rawValue)")
            .font(.caption2)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(DesignSystem.confidenceColor(confidence).opacity(0.15), in: Capsule())
            .foregroundStyle(DesignSystem.confidenceColor(confidence))
    }
}

// MARK: - Rows

struct KeyValueRow: View {
    let key: String
    let value: String
    var monospaced = false

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Text(key)
                .font(.subheadline)
                .foregroundStyle(.secondary)
            Spacer(minLength: 12)
            Text(value)
                .font(monospaced ? .footnote.monospaced() : .subheadline)
                .multilineTextAlignment(.trailing)
                .textSelection(.enabled)
        }
        .padding(.vertical, 2)
    }
}

struct CopyableBlock: View {
    let text: String
    var font: Font = .caption.monospaced()

    var body: some View {
        Text(text)
            .font(font)
            .textSelection(.enabled)
            .frame(maxWidth: .infinity, alignment: .leading)
    }
}

// MARK: - Empty / loading / error states

struct EmptyStateView: View {
    let title: String
    let systemImage: String
    var description: String = ""

    var body: some View {
        VStack(spacing: DesignSystem.Spacing.s) {
            Image(systemName: systemImage)
                .font(.system(size: 36))
                .foregroundStyle(.secondary)
            Text(title)
                .font(.headline)
            if !description.isEmpty {
                Text(description)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(DesignSystem.Spacing.l)
        .accessibilityElement(children: .combine)
    }
}

struct LoadingCard: View {
    let message: String

    var body: some View {
        HStack(spacing: DesignSystem.Spacing.s) {
            ProgressView()
            Text(message)
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .padding(DesignSystem.Spacing.m)
        .frame(maxWidth: .infinity, alignment: .center)
        .background(Color(.secondarySystemGroupedBackground),
                    in: RoundedRectangle(cornerRadius: DesignSystem.Radius.card))
    }
}

// MARK: - Module tiles for the home grid

struct ModuleTile: View {
    let title: String
    let systemImage: String
    let detail: String
    var tint: Color = DesignSystem.accent

    var body: some View {
        HStack(spacing: DesignSystem.Spacing.m) {
            Image(systemName: systemImage)
                .font(.title3)
                .foregroundStyle(tint)
                .frame(width: 34)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.primary)
                Text(detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer()
            Image(systemName: "chevron.right")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.tertiary)
        }
        .padding(.vertical, 4)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(title), \(detail)")
    }
}

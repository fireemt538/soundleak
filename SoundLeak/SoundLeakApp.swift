import SwiftUI
import AVFoundation
import Security
import UniformTypeIdentifiers

// MARK: - Constants

let containerRoot = "/var/mobile/Containers/Data/Application"

// MARK: - worse_query bridge

enum WQ {
    static var group: String?

    static func resolveGroup() -> String? {
        var candidates: [String] = []
        if let task = SecTaskCreateFromSelf(nil),
           let raw = SecTaskCopyValueForEntitlement(task, "com.apple.security.application-groups" as CFString, nil),
           let list = raw as? [String] {
            candidates = list
        }
        candidates.append("group.cc.soundleak.app")
        return candidates.first {
            FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: $0) != nil
        }
    }

    static func consume(_ path: String, createDir: Bool = false) -> Int64 {
        guard let group else { return -1 }
        let isGroupPath = path.contains("/var/mobile/Containers/Shared/AppGroup")
        let is26 = ProcessInfo.processInfo.operatingSystemVersion.majorVersion == 26
        let alt = isGroupPath && is26
        return worse_query(path, group, alt, createDir)
    }

    static func release(_ handle: Int64) { if handle > 0 { worse_query_release(handle) } }

    static func bundleID(at path: String) -> String? {
        var buf = [CChar](repeating: 0, count: 1024)
        let n = getxattr(path, "com.apple.containermanager.identifier", &buf, 1023, 0, 0)
        guard n > 0 else { return nil }
        return String(cString: buf)
    }

    static func isWritable(_ path: String) -> Bool { access(path, W_OK) == 0 }

    static func fileSize(_ path: String) -> Int64 {
        ((try? FileManager.default.attributesOfItem(atPath: path))?[.size] as? Int64) ?? 0
    }
}

// MARK: - Models

struct SoundFile: Identifiable, Hashable {
    let path: String
    let name: String
    let size: Int64
    let systemPlayable: Bool
    let writable: Bool
    var id: String { path }
    var url: URL { URL(fileURLWithPath: path) }
    var ext: String { (name as NSString).pathExtension.lowercased() }
    var sizeText: String { ByteCountFormatter.string(fromByteCount: size, countStyle: .file) }
}

struct AppHit: Identifiable, Hashable {
    let bundleID: String
    let containerPath: String
    let soundsPath: String
    let hasSoundsDir: Bool
    let writeVerified: Bool
    var files: [SoundFile]
    var id: String { containerPath }
    var displayName: String {
        let tail = bundleID.split(separator: ".").last.map(String.init) ?? bundleID
        return tail.replacingOccurrences(of: "-", with: " ").capitalized
    }
    var editableCount: Int { files.filter(\.writable).count }
    var sortKey: String { displayName.lowercased() }
}

// MARK: - Store

@MainActor
final class Store: ObservableObject {
    @Published var apps: [AppHit] = []
    @Published var scanning = false
    @Published var status = "Idle"
    @Published var log: [String] = []
    @Published var thorough: Double = 1.0
    @Published var includeCreatable = false
    @Published var fatal: String?
    @Published var scanned = 0

    private let queue = DispatchQueue(label: "cc.soundleak.scan", qos: .userInitiated)
    nonisolated(unsafe) private var cancelled = false

    nonisolated init() {}

    func bootstrap() {
        WQ.group = WQ.resolveGroup()
        if WQ.group == nil {
            fatal = "No App Group. Re-sign with AltStore or SideStore so one gets provisioned."
        }
    }

    func scan() {
        guard !scanning, fatal == nil else { return }
        scanning = true
        cancelled = false
        apps = []
        scanned = 0
        status = "Starting…"
        let t = thorough
        let c = includeCreatable
        queue.async { self.performScan(thorough: t, includeCreatable: c) }
    }

    func cancel() { cancelled = true; status = "Cancelling…" }

    private nonisolated func performScan(thorough: Double, includeCreatable: Bool) {
        func report(_ s: String) { Task { @MainActor in self.status = s } }
        func note(_ s: String) { Task { @MainActor in self.log.append(s) } }

        let root = containerRoot
        let rootHandle = WQ.consume(root)
        guard rootHandle > 0 else {
            Task { @MainActor in
                self.scanning = false
                self.fatal = "worse_query failed on the container root (handle \(rootHandle))."
            }
            return
        }
        defer { WQ.release(rootHandle) }

        let baseline = FileManager.default.temporaryDirectory
            .appendingPathComponent(".bl_\(UUID().uuidString)")
        var ceiling: UInt64 = 2_000_000
        if (try? Data("p".utf8).write(to: baseline)) != nil {
            var st = stat()
            if stat(baseline.path, &st) == 0, st.st_ino > 0 {
                ceiling = UInt64(Double(st.st_ino) * max(thorough, 1))
            }
            try? FileManager.default.removeItem(at: baseline)
        }
        note("inode ceiling \(ceiling)")

        report("Leaking container paths…")
        let paths = pathleak(root, ceiling) ?? []
        note("\(paths.count) candidates")

        var hits: [AppHit] = []
        let own = Bundle.main.bundleIdentifier

        for (i, path) in paths.enumerated() {
            if cancelled { break }
            if i % 25 == 0 {
                report("Inspecting \(i)/\(paths.count)…")
                Task { @MainActor in self.scanned = i }
            }
            let handle = WQ.consume(path)
            guard handle > 0 else { continue }
            defer { WQ.release(handle) }
            guard let bid = WQ.bundleID(at: path), bid != own else { continue }
            if let hit = inspect(container: path, bundleID: bid, includeCreatable: includeCreatable) {
                hits.append(hit)
            }
        }

        let sorted = hits.sorted { $0.sortKey < $1.sortKey }
        Task { @MainActor in
            self.apps = sorted
            self.scanning = false
            self.status = self.cancelled ? "Cancelled — \(sorted.count)" : "Done — \(sorted.count) apps"
        }
    }

    private nonisolated func inspect(container: String, bundleID: String, includeCreatable: Bool) -> AppHit? {
        let fm = FileManager.default
        let sounds = container + "/Library/Sounds"
        let library = container + "/Library"

        var isDir: ObjCBool = false
        let hasDir = fm.fileExists(atPath: sounds, isDirectory: &isDir) && isDir.boolValue
        guard hasDir || (includeCreatable && WQ.isWritable(library)) else { return nil }

        if !hasDir {
            return AppHit(bundleID: bundleID, containerPath: container, soundsPath: sounds,
                          hasSoundsDir: false, writeVerified: false, files: [])
        }

        var files: [SoundFile] = []
        let names = ((try? fm.contentsOfDirectory(atPath: sounds)) ?? []).sorted()
        for name in names where !name.hasPrefix(".") {
            let p = sounds + "/" + name
            var d: ObjCBool = false
            guard fm.fileExists(atPath: p, isDirectory: &d), !d.boolValue else { continue }
            let ext = (name as NSString).pathExtension.lowercased()
            files.append(SoundFile(path: p, name: name, size: WQ.fileSize(p),
                                   systemPlayable: ["caf", "wav", "aiff", "aif"].contains(ext),
                                   writable: WQ.isWritable(p)))
        }

        let probe = sounds + "/.soundleak_probe"
        let verified = (try? Data().write(to: URL(fileURLWithPath: probe))) != nil
        if verified { try? fm.removeItem(atPath: probe) }

        guard !files.isEmpty || verified else { return nil }
        return AppHit(bundleID: bundleID, containerPath: container, soundsPath: sounds,
                      hasSoundsDir: true, writeVerified: verified, files: files)
    }

    func delete(_ file: SoundFile, in hit: AppHit) {
        let h = WQ.consume(hit.containerPath)
        guard h > 0 else { return }
        defer { WQ.release(h) }
        try? FileManager.default.removeItem(atPath: file.path)
        refresh(hit)
    }

    func makeSoundsDir(for hit: AppHit) {
        let h = WQ.consume(hit.containerPath)
        guard h > 0 else { return }
        defer { WQ.release(h) }
        try? FileManager.default.createDirectory(atPath: hit.soundsPath, withIntermediateDirectories: true)
        refresh(hit)
    }

    func export(_ file: SoundFile, from hit: AppHit) -> URL? {
        let h = WQ.consume(hit.containerPath)
        guard h > 0 else { return nil }
        defer { WQ.release(h) }
        let dest = FileManager.default.temporaryDirectory.appendingPathComponent(file.name)
        try? FileManager.default.removeItem(at: dest)
        try? FileManager.default.copyItem(at: file.url, to: dest)
        return FileManager.default.fileExists(atPath: dest.path) ? dest : nil
    }

    func importSound(from url: URL, into hit: AppHit) -> String? {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }

        let h = WQ.consume(hit.containerPath)
        guard h > 0 else { return "No container access." }
        defer { WQ.release(h) }

        try? FileManager.default.createDirectory(atPath: hit.soundsPath, withIntermediateDirectories: true)
        let dest = hit.soundsPath + "/" + url.lastPathComponent
        do {
            if FileManager.default.fileExists(atPath: dest) {
                try FileManager.default.removeItem(atPath: dest)
            }
            try FileManager.default.copyItem(at: url, to: URL(fileURLWithPath: dest))
        } catch { return error.localizedDescription }

        refresh(hit)

        let ext = url.pathExtension.lowercased()
        if !["caf", "wav", "aiff", "aif"].contains(ext) {
            return "Copied, but iOS won't play .\(ext) for notifications. Convert to caf/wav/aiff."
        }
        if let p = try? AVAudioPlayer(contentsOf: URL(fileURLWithPath: dest)), p.duration > 30 {
            return "Copied, but it's \(Int(p.duration))s. iOS cuts notification sounds at 30s."
        }
        return nil
    }

    private func refresh(_ hit: AppHit) {
        let h = WQ.consume(hit.containerPath)
        defer { WQ.release(h) }
        var files: [SoundFile] = []
        let names = ((try? FileManager.default.contentsOfDirectory(atPath: hit.soundsPath)) ?? []).sorted()
        for name in names where !name.hasPrefix(".") {
            let p = hit.soundsPath + "/" + name
            let ext = (name as NSString).pathExtension.lowercased()
            files.append(SoundFile(path: p, name: name, size: WQ.fileSize(p),
                                   systemPlayable: ["caf", "wav", "aiff", "aif"].contains(ext),
                                   writable: WQ.isWritable(p)))
        }
        if let i = apps.firstIndex(where: { $0.containerPath == hit.containerPath }) {
            apps[i].files = files
        }
    }
}

// MARK: - Preview

final class Previewer: ObservableObject {
    static let shared = Previewer()
    @Published var playing: String?
    private var player: AVAudioPlayer?
    private var handle: Int64 = -1

    func toggle(_ file: SoundFile, container: String) {
        if playing == file.path { stop(); return }
        stop()
        handle = WQ.consume(container)
        guard handle > 0 else { return }
        do {
            let s = AVAudioSession.sharedInstance()
            try s.setCategory(.playback, mode: .default)
            try s.setActive(true)
            player = try AVAudioPlayer(contentsOf: file.url)
            player?.play()
            playing = file.path
        } catch { stop() }
    }

    func stop() {
        player?.stop()
        player = nil
        WQ.release(handle)
        handle = -1
        playing = nil
    }
}

// MARK: - UI

struct ContentView: View {
    @StateObject private var store = Store()
    @State private var query = ""
    @State private var showSettings = false

    private var filtered: [AppHit] {
        guard !query.isEmpty else { return store.apps }
        return store.apps.filter {
            $0.bundleID.localizedCaseInsensitiveContains(query)
                || $0.files.contains { $0.name.localizedCaseInsensitiveContains(query) }
        }
    }

    var body: some View {
        NavigationStack {
            Group {
                if let fatal = store.fatal {
                    ContentUnavailableView("No App Group", systemImage: "square.stack.3d.up.slash",
                                           description: Text(fatal))
                } else if store.apps.isEmpty && !store.scanning {
                    ContentUnavailableView("Nothing Scanned", systemImage: "waveform",
                                           description: Text("Scan to list apps with editable notification sounds."))
                } else {
                    List {
                        if store.scanning {
                            Section {
                                HStack(spacing: 12) {

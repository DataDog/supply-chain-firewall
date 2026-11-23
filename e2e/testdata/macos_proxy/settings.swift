// Native macOS fixture; never linked into SCFW. Property lists preserve the
// entire Proxies protocol, including absent/disabled/empty/authenticated state.
import Foundation
import SystemConfiguration

struct FixtureError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}
func require(_ ok: Bool, _ action: String) throws {
    if !ok { throw FixtureError("\(action): SystemConfiguration error \(SCError())") }
}
func effective() throws -> NSDictionary {
    guard let value = SCDynamicStoreCopyProxies(nil) else {
        throw FixtureError("cannot read effective proxy settings")
    }
    return value as NSDictionary
}
func activeService() throws -> String {
    guard let store = SCDynamicStoreCreate(nil, "scfw-e2e" as CFString, nil, nil) else {
        throw FixtureError("cannot open dynamic store")
    }
    var services = Set<String>()
    for family in ["IPv4", "IPv6"] {
        if let state = SCDynamicStoreCopyValue(store, "State:/Network/Global/\(family)" as CFString) as? [String: Any],
           let id = state["PrimaryService"] as? String { services.insert(id) }
    }
    guard services.count == 1, let id = services.first else {
        throw FixtureError("need one unambiguous active IPv4/IPv6 network service")
    }
    return id
}
func stored(_ service: SCNetworkService) -> [String: Any] {
    guard let proto = SCNetworkServiceCopyProtocol(service, kSCNetworkProtocolTypeProxies) else {
        return ["present": false]
    }
    var value: [String: Any] = ["present": true, "enabled": SCNetworkProtocolGetEnabled(proto)]
    if let config = SCNetworkProtocolGetConfiguration(proto) { value["configuration"] = config }
    return value
}
func snapshot(_ service: SCNetworkService, _ id: String) throws -> [String: Any] {
    return ["service_id": id, "service_name": SCNetworkServiceGetName(service) as String? ?? "",
            "stored": stored(service), "effective": try effective()]
}
func emit(_ value: [String: Any]) throws {
    let data = try PropertyListSerialization.data(fromPropertyList: value, format: .xml, options: 0)
    FileHandle.standardOutput.write(data)
}
func readSnapshot(_ path: String) throws -> [String: Any] {
    let data = try Data(contentsOf: URL(fileURLWithPath: path))
    guard let value = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any] else {
        throw FixtureError("invalid snapshot")
    }
    return value
}
func setStored(_ service: SCNetworkService, _ value: [String: Any]) throws {
    guard let present = value["present"] as? Bool else { throw FixtureError("snapshot has no protocol presence") }
    if !present {
        if SCNetworkServiceCopyProtocol(service, kSCNetworkProtocolTypeProxies) != nil {
            try require(SCNetworkServiceRemoveProtocolType(service, kSCNetworkProtocolTypeProxies), "remove protocol")
        }
        return
    }
    if SCNetworkServiceCopyProtocol(service, kSCNetworkProtocolTypeProxies) == nil {
        try require(SCNetworkServiceAddProtocolType(service, kSCNetworkProtocolTypeProxies), "add protocol")
    }
    guard let proto = SCNetworkServiceCopyProtocol(service, kSCNetworkProtocolTypeProxies),
          let enabled = value["enabled"] as? Bool else { throw FixtureError("missing protocol or enabled state") }
    let configuration = value["configuration"] as? NSDictionary
    try require(SCNetworkProtocolSetConfiguration(proto, configuration as CFDictionary?), "set configuration")
    try require(SCNetworkProtocolSetEnabled(proto, enabled), "set enabled")
}
func waitFor(_ predicate: () throws -> Bool) throws {
    let end = Date().addingTimeInterval(15)
    repeat {
        if try predicate() { return }
        Thread.sleep(forTimeInterval: 0.1)
    } while Date() < end
    throw FixtureError("effective proxy settings did not converge within 15 seconds")
}
func main() throws {
    let args = CommandLine.arguments
    guard args.count >= 3, ["snapshot", "apply", "restore"].contains(args[1]) else {
        throw FixtureError("usage: settings snapshot|apply|restore service-id [proxy-url bypass-host|snapshot-path]")
    }
    let action = args[1], id = args[2]
    guard let prefs = SCPreferencesCreate(nil, "scfw-e2e" as CFString, nil) else {
        throw FixtureError("cannot open preferences")
    }
    try require(SCPreferencesLock(prefs, false), "lock preferences")
    var locked = true
    defer { if locked { SCPreferencesUnlock(prefs) } }
    guard let service = SCNetworkServiceCopy(prefs, id as CFString) else { throw FixtureError("unknown service ID") }
    // Restoration still repairs the selected service if routing changed meanwhile.
    if action != "restore" {
        guard try activeService() == id else { throw FixtureError("selected service is not the active service") }
    }
    if action == "snapshot" {
        guard args.count == 3 else { throw FixtureError("snapshot takes only service ID") }
        try emit(snapshot(service, id))
        return
    }
    var original: [String: Any] = [:]
    var desired: [String: Any]
    if action == "restore" {
        guard args.count == 4 else { throw FixtureError("restore requires snapshot path") }
        original = try readSnapshot(args[3])
        guard original["service_id"] as? String == id,
              let state = original["stored"] as? [String: Any], original["effective"] is NSDictionary else {
            throw FixtureError("snapshot does not describe this service")
        }
        desired = state
    } else {
        guard args.count == 5, let proxy = URLComponents(string: args[3]), proxy.scheme == "http",
              proxy.host == "127.0.0.1", let port = proxy.port, (1...65535).contains(port),
              proxy.user == nil, proxy.password == nil else { throw FixtureError("need a loopback HTTP proxy and optional bypass host") }
        let exceptions = args[4].isEmpty ? [] : [args[4]]
        desired = ["present": true, "enabled": true, "configuration": [
            "HTTPEnable": 1, "HTTPProxy": "127.0.0.1", "HTTPPort": port,
            "HTTPSEnable": 1, "HTTPSProxy": "127.0.0.1", "HTTPSPort": port,
            "ExceptionsList": exceptions, "ExcludeSimpleHostnames": 0,
            "ProxyAutoConfigEnable": 0, "ProxyAutoDiscoveryEnable": 0, "SOCKSEnable": 0]]
    }
    try setStored(service, desired)
    try require(SCPreferencesCommitChanges(prefs), "commit preferences")
    try require(SCPreferencesApplyChanges(prefs), "apply preferences")
    try require(SCPreferencesUnlock(prefs), "unlock preferences")
    locked = false
    // A fresh preferences session verifies durable settings, not our in-memory edit.
    guard let checkPrefs = SCPreferencesCreate(nil, "scfw-e2e-verify" as CFString, nil),
          let checkService = SCNetworkServiceCopy(checkPrefs, id as CFString),
          NSDictionary(dictionary: stored(checkService)).isEqual(to: desired) else {
        throw FixtureError("stored proxy settings differ from requested settings")
    }
    try waitFor {
        let current = try effective()
        if action == "restore" {
            return current.isEqual(original["effective"])
        }
        guard let config = desired["configuration"] as? [String: Any] else { return false }
        // Empty exceptions/disabled options can be omitted from the dynamic store.
        for key in ["HTTPEnable", "HTTPProxy", "HTTPPort", "HTTPSEnable", "HTTPSProxy", "HTTPSPort"] {
            if (current[key] as? NSObject)?.isEqual(config[key]) != true { return false }
        }
        return (current["ExceptionsList"] as? [String] ?? []) == (config["ExceptionsList"] as? [String] ?? [])
            && (current["ProxyAutoConfigEnable"] as? Int ?? 0) == 0
            && (current["ProxyAutoDiscoveryEnable"] as? Int ?? 0) == 0
            && (current["SOCKSEnable"] as? Int ?? 0) == 0
    }
    try emit(snapshot(checkService, id))
}
do { try main() } catch {
    FileHandle.standardError.write(Data("\(error)\n".utf8))
    exit(1)
}

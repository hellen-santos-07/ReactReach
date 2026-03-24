function computeReachability(dependencyUsages, components, sinks) {
  const findings = [];

  for (const usage of dependencyUsages) {
    const fileComponents = components.filter(c => c.filePath === usage.filePath);
    const fileSinks = sinks.filter(s => s.filePath === usage.filePath);

    if (fileComponents.length > 0 && fileSinks.length > 0) {
      findings.push({
        packageName: usage.packageName,
        filePath: usage.filePath,
        reachability: "HIGH",
        reason: "Vulnerable dependency usage and security sink found in same React file",
        components: fileComponents.map(c => c.name),
        sinks: fileSinks.map(s => s.sinkType)
      });
    } else if (fileComponents.length > 0) {
      findings.push({
        packageName: usage.packageName,
        filePath: usage.filePath,
        reachability: "MEDIUM",
        reason: "Vulnerable dependency used inside a React component file, but no sink found in same file",
        components: fileComponents.map(c => c.name),
        sinks: []
      });
    } else {
      findings.push({
        packageName: usage.packageName,
        filePath: usage.filePath,
        reachability: "LOW",
        reason: "Vulnerable dependency imported, but no React component context identified",
        components: [],
        sinks: []
      });
    }
  }

  return findings;
}

module.exports = computeReachability;
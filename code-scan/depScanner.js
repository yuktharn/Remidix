// depScanner.js
// Checks dependencies (from a pasted/uploaded package.json) against OSV.dev —
// a free, open, real-time vulnerability database used by GitHub and Google.
// No API key required. This covers the "unsafe dependencies" requirement
// from the problem statement.

const OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_URL = "https://api.osv.dev/v1/vulns";

function parsePackageJson(content) {
  let parsed;
  try {
    parsed = JSON.parse(content);
  } catch {
    return [];
  }
  const deps = { ...(parsed.dependencies || {}), ...(parsed.devDependencies || {}) };
  return Object.entries(deps).map(([name, versionRange]) => ({
    name,
    // strip ^ ~ >= etc. so we send OSV a concrete version to check
    version: String(versionRange).replace(/^[\^~>=<]+/, ""),
  }));
}

function severityFromOSV(vuln) {
  const sev = vuln?.severity?.[0]?.score;
  if (!sev) return "Medium";
  const score = parseFloat(sev);
  if (!isNaN(score)) {
    if (score >= 9) return "Critical";
    if (score >= 7) return "High";
    if (score >= 4) return "Medium";
    return "Low";
  }
  return "Medium";
}

// Pulls the first "fixed" version out of an OSV vuln's affected/ranges/events
// for the given package name, if one is published. Returns null if OSV
// doesn't specify a fixed version (common for ranges that are still open).
function extractFixedVersion(detail, packageName) {
  if (!Array.isArray(detail.affected)) return null;
  for (const aff of detail.affected) {
    if (aff.package?.name && aff.package.name !== packageName) continue;
    for (const range of aff.ranges || []) {
      for (const event of range.events || []) {
        if (event.fixed) return event.fixed;
      }
    }
  }
  return null;
}

async function scanDependencies(packageJsonContent) {
  const packages = parsePackageJson(packageJsonContent);
  if (packages.length === 0) return [];

  try {
    const batchRes = await fetch(OSV_BATCH_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        queries: packages.map((p) => ({
          package: { name: p.name, ecosystem: "npm" },
          version: p.version,
        })),
      }),
    });

    if (!batchRes.ok) {
      console.error("OSV batch query failed:", batchRes.status);
      return [];
    }

    const batchData = await batchRes.json();
    const findings = [];

    for (let i = 0; i < packages.length; i++) {
      const vulns = batchData.results?.[i]?.vulns || [];
      // cap at 3 per package so one badly-outdated dependency doesn't blow up the scan
      for (const v of vulns.slice(0, 3)) {
        let detail = v;
        try {
          const detailRes = await fetch(`${OSV_VULN_URL}/${v.id}`);
          if (detailRes.ok) detail = await detailRes.json();
        } catch {
          // fine — we fall back to a generic message below
        }

        findings.push({
          type: "Vulnerable Dependency",
          category: "Unsafe Dependencies",
          severity: severityFromOSV(detail),
          line: null,
          packageName: packages[i].name,
          version: packages[i].version,
          vulnId: v.id,
          publishedDate: detail.published || null,
          fixedVersion: extractFixedVersion(detail, packages[i].name),
          osvUrl: `https://osv.dev/vulnerability/${v.id}`,
          explanation: detail.summary || `${packages[i].name}@${packages[i].version} has a known vulnerability (${v.id}).`,
          fix: `Upgrade ${packages[i].name} past the affected range. See ${v.id} for the patched version.`,
          confidence: 0.95,
          method: "dependency",
          matchPreview: `${packages[i].name}@${packages[i].version}`,
        });
      }
    }

    return findings;
  } catch (err) {
    console.error("Dependency scan failed:", err.message);
    return [];
  }
}

module.exports = { scanDependencies };
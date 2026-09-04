// depScanner.js

// Checks dependencies from a pasted/uploaded package.json against OSV.dev.
// OSV is a public vulnerability database used for dependency security analysis.
// Generates dependency findings with affected lines and available fixed versions.

const OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_URL = "https://api.osv.dev/v1/vulns";

function parsePackageJson(content) {
  let parsed;

  try {
    parsed = JSON.parse(content);
  } catch {
    return [];
  }

  const dependencies = {
    ...(parsed.dependencies || {}),
    ...(parsed.devDependencies || {}),
  };

  return Object.entries(dependencies).map(([name, versionRange]) => ({
    name,
    version: String(versionRange).replace(/^[\^~>=<]+/, ""),
    rawVersion: String(versionRange),
  }));
}

function severityFromOSV(vulnerability) {
  const cvssScore = vulnerability?.severity?.[0]?.score;

  if (cvssScore) {
    const score = parseFloat(cvssScore);

    if (!Number.isNaN(score)) {
      if (score >= 9) return "Critical";
      if (score >= 7) return "High";
      if (score >= 4) return "Medium";

      return "Low";
    }
  }

  const ghsaSeverity =
    vulnerability?.database_specific?.severity;

  if (ghsaSeverity) {
    const map = {
      CRITICAL: "Critical",
      HIGH: "High",
      MODERATE: "Medium",
      LOW: "Low",
    };

    if (map[ghsaSeverity]) {
      return map[ghsaSeverity];
    }
  }

  return "High";
}

function extractFixedVersion(detail, packageName) {
  if (!Array.isArray(detail?.affected)) {
    return null;
  }

  for (const affected of detail.affected) {
    if (
      affected.package?.name &&
      affected.package.name !== packageName
    ) {
      continue;
    }

    for (const range of affected.ranges || []) {
      for (const event of range.events || []) {
        if (event.fixed) {
          return event.fixed;
        }
      }
    }
  }

  return null;
}

function findDependencyLine(lines, packageName) {
  const escapedPackageName = packageName.replace(
    /[.*+?^${}()|[\]\\]/g,
    "\\$&"
  );

  const pattern = new RegExp(
    `"${escapedPackageName}"\\s*:`
  );

  for (let index = 0; index < lines.length; index++) {
    if (pattern.test(lines[index])) {
      return index + 1;
    }
  }

  return 1;
}

async function scanDependencies(packageJsonContent) {
  const packages = parsePackageJson(packageJsonContent);

  if (packages.length === 0) {
    return [];
  }

  const lines = packageJsonContent.split(/\r?\n/);

  try {
    const batchResponse = await fetch(OSV_BATCH_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        queries: packages.map((pkg) => ({
          package: {
            name: pkg.name,
            ecosystem: "npm",
          },
          version: pkg.version,
        })),
      }),
    });

    if (!batchResponse.ok) {
      console.error(
        "OSV batch query failed:",
        batchResponse.status,
        batchResponse.statusText
      );

      return [];
    }

    const batchData = await batchResponse.json();

    const findings = [];

    for (let index = 0; index < packages.length; index++) {
      const pkg = packages[index];

      const vulnerabilities =
        batchData.results?.[index]?.vulns || [];

      if (vulnerabilities.length === 0) {
        continue;
      }

      const lineNumber = findDependencyLine(
        lines,
        pkg.name
      );

      for (const vulnerability of vulnerabilities.slice(0, 3)) {
        let detail = vulnerability;

        try {
          const detailResponse = await fetch(
            `${OSV_VULN_URL}/${encodeURIComponent(vulnerability.id)}`
          );

          if (detailResponse.ok) {
            detail = await detailResponse.json();
          }
        } catch (error) {
          // Use the batch response if the detailed request fails.
          console.warn(
            `Could not retrieve OSV details for ${vulnerability.id}:`,
            error.message
          );
        }

        const fixedVersion =
          extractFixedVersion(detail, pkg.name);

        const vulnerableSnippet =
          `"${pkg.name}": "${pkg.rawVersion}"`;

        const correctedSnippet = fixedVersion
          ? `"${pkg.name}": "^${fixedVersion}"`
          : `"${pkg.name}": "${pkg.rawVersion}"`;

        const summary =
          detail.summary ||
          `${pkg.name}@${pkg.version} has a known public vulnerability (${vulnerability.id}).`;

        const vulnerabilityUrl =
          `https://osv.dev/vulnerability/${encodeURIComponent(
            vulnerability.id
          )}`;

        const remediation = fixedVersion
          ? `Upgrade "${pkg.name}" to version ${fixedVersion} or later. Example: npm install ${pkg.name}@${fixedVersion}`
          : `Check the OSV advisory ${vulnerability.id} for the currently recommended patched version of "${pkg.name}".`;

        findings.push({
          type: `Outdated Dependency: ${pkg.name}`,

          category: "Outdated Dependencies",

          severity: severityFromOSV(detail),

          line: lineNumber,
          lineEnd: lineNumber,

          packageName: pkg.name,

          version: pkg.version,

          vulnId: vulnerability.id,

          publishedDate:
            detail.published || null,

          fixedVersion,

          osvUrl: vulnerabilityUrl,

          vulnerableCode: vulnerableSnippet,

          correctedCode: correctedSnippet,

          cwe:
            "CWE-1395: Dependency on Vulnerable Third-Party Component",

          owasp:
            "A06:2021-Vulnerable and Outdated Components",

          explanation: summary,

          impact:
            "Attackers may exploit a known vulnerability in the affected dependency to compromise application confidentiality, integrity, or availability, depending on the advisory and how the dependency is used.",

          fix: remediation,

          confidence: 0.98,

          method: "dependency",

          matchPreview:
            `${pkg.name}@${pkg.version}`,

          status: "open",
        });
      }
    }

    return findings;
  } catch (error) {
    console.error(
      "Dependency scan failed:",
      error.message
    );

    return [];
  }
}

module.exports = {
  scanDependencies,
};
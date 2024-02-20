"use strict";
const core = require("@actions/core");
const { Octokit } = require("@octokit/action");
const github = require("@actions/github");

const repository = core.getInput("repository") || github.context.payload.repository.full_name;
const severityThreshold = core.getInput("severity") || 'high';
const allowNotFound = core.getInput("allow-not-found");
const failAction = core.getInput("fail-action");

async function run() {
  const alerts = [];
  try {
    //Validate input
    const alllow_severity = ["critical", "high", "moderate", "medium", "low"]
    if(!alllow_severity.includes(severityThreshold)){
      core.setFailed(`Expected: "critical", "high", "moderate", "medium", "low" for severity Found: ${severityThreshold}`);

    }

    const octokit = new Octokit();
    core.info(
      `Checking for Code Scanning`
    );
    const { data: codeScanData } = await octokit.request(
      `GET /repos/${repository}/code-scanning/alerts{?per_page,state}`,
      {
        per_page: 100,
        state: "open",
      }
    );
    if (
      codeScanData.message === "no analysis found" &&
      allowNotFound !== "true"
    ) {
      core.setFailed(`No code scanning results!`);
    }
    const filteredCodeScanResults = codeScanData.filter((item) => {
      let severity = item.rule.security_severity_level || item.rule.severity;
      return toSeverityLevel(severity) >= toSeverityLevel(severityThreshold);
    });
    if (filteredCodeScanResults.length > 0) {
      alerts.push(
        `Found ${filteredCodeScanResults.length} code scan issues with ${severityThreshold} severity and above`
      );
    }
    core.info(
      `Checking for Dependabot`
    );
    const { data: dependabotData } = await octokit.request(`GET /repos/${repository}/dependabot/alerts?state=open`)

    const filteredDependabotResults = dependabotData.filter(obj=> obj.state === "open" &&
          toSeverityLevel(obj.security_advisory.severity) >=
            toSeverityLevel(severityThreshold));

    if (filteredDependabotResults.length > 0) {
      alerts.push(
        `Found ${filteredDependabotResults.length} dependency vulnerabilities with ${severityThreshold} severity and above`
      );
    }

    core.info(
      `Checking for Secret Scanning`
    );
    const { data: secretScanData } = await octokit.request(
      `GET /repos/${repository}/secret-scanning/alerts{?per_page,state}`,
      {
        per_page: 100,
        state: "open",
      }
    );
    if (secretScanData.length > 0) {
      alerts.push(`Found ${secretScanData.length} secret scanning alerts`);
    }

    if (alerts.length > 0) {
      if (failAction === "true") {
        core.setFailed(alerts.join("\n"));
      } else {
        core.warning(alerts.join("\n"));
      }
    } else {
      core.info(
        `No security alerts with ${severityThreshold} severity and above detected`
      );
    }
  } catch (error) {
    core.setFailed(error.message);
  }
}

const toSeverityLevel = (severity) => {
  switch (severity.toLowerCase()) {
    case "critical":
      return 4;
    case "high":
      return 3;
    case "moderate":
    case "medium":
      return 2;
    case "low":
      return 1;
    default:
      return 0;
  }
};

run();

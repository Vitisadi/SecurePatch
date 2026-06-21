#!/usr/bin/env node
import * as fs from "fs";
import * as path from "path";
import { RegexDetector } from "./detectors/regexDetector";

/**
 * Thin command-line bridge over the core detection engine. The Python research
 * harness shells out to this and parses the JSON on stdout. All diagnostics go
 * to stderr so stdout stays machine-parseable.
 *
 * Usage:
 *   securepatch-core scan <file>
 */

const SCHEMA_VERSION = 1;

async function main(): Promise<number> {
  const args = process.argv.slice(2);
  const command = args[0];

  if (!command || command === "--help" || command === "-h") {
    printUsage();
    return command ? 0 : 2;
  }

  if (command !== "scan") {
    process.stderr.write(`Unknown command: ${command}\n`);
    printUsage();
    return 2;
  }

  const fileArg = args.slice(1).find((arg) => !arg.startsWith("-"));
  if (!fileArg) {
    process.stderr.write("Error: scan requires a <file> argument.\n");
    return 2;
  }

  const absolutePath = path.resolve(fileArg);
  let content: string;
  try {
    content = fs.readFileSync(absolutePath, "utf8");
  } catch (error) {
    process.stderr.write(`Error: cannot read file ${absolutePath}: ${describe(error)}\n`);
    return 2;
  }

  const detector = new RegexDetector();
  const findings = await detector.detect(absolutePath, content);

  process.stdout.write(
    JSON.stringify(
      {
        schemaVersion: SCHEMA_VERSION,
        detector: detector.name,
        file: absolutePath,
        findingCount: findings.length,
        findings
      },
      null,
      2
    ) + "\n"
  );

  return 0;
}

function printUsage(): void {
  process.stderr.write(
    [
      "securepatch-core — detection bridge for the SecurePatch research harness",
      "",
      "Usage:",
      "  securepatch-core scan <file>    Scan one file, print findings as JSON to stdout",
      ""
    ].join("\n")
  );
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

main()
  .then((code) => process.exit(code))
  .catch((error) => {
    process.stderr.write(`Fatal: ${error instanceof Error ? (error.stack ?? error.message) : String(error)}\n`);
    process.exit(1);
  });

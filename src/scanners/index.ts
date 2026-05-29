import * as path from "path";
import { scanCode } from "./codeScanner";
import { scanDependencies } from "./dependencyScanner";
import { SecurityFinding } from "../types/finding";

const supportedSourceExtensions = new Set([".js", ".ts", ".py"]);
const supportedDependencyFiles = new Set(["package.json", "requirements.txt"]);

export function isSupportedFile(filePath: string): boolean {
  const baseName = path.basename(filePath).toLowerCase();
  return supportedSourceExtensions.has(path.extname(filePath).toLowerCase()) || supportedDependencyFiles.has(baseName);
}

export function scanFile(filePath: string, content: string): SecurityFinding[] {
  const baseName = path.basename(filePath).toLowerCase();

  if (supportedDependencyFiles.has(baseName)) {
    return scanDependencies(filePath, content);
  }

  if (supportedSourceExtensions.has(path.extname(filePath).toLowerCase())) {
    return scanCode(filePath, content);
  }

  return [];
}

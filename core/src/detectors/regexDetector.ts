import { Detector } from "../interfaces/detector";
import { SecurityFinding } from "../types/finding";
import { isSupportedFile, scanFile } from "../scanners";

/**
 * The current rule-based detector, wrapped in the Detector interface. This is
 * the baseline the research harness compares AI detectors against.
 */
export class RegexDetector implements Detector {
  readonly name = "regex";

  async detect(filePath: string, content: string): Promise<SecurityFinding[]> {
    if (!isSupportedFile(filePath)) {
      return [];
    }

    return scanFile(filePath, content);
  }
}

// Public surface of @securepatch/core. Consumed by the VS Code extension and by
// the CLI that the Python research harness shells out to.

export * from "./types/finding";
export * from "./types/aiSuggestion";

export * from "./interfaces/detector";
export * from "./interfaces/fixer";
export * from "./interfaces/modelProvider";

export * from "./detectors/regexDetector";

export { isSupportedFile, scanFile } from "./scanners";

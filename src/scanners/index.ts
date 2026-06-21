// Detection logic now lives in @securepatch/core (shared with the research
// harness). Re-exported so the extension can keep importing from "./scanners".
export { isSupportedFile, scanFile } from "@securepatch/core";

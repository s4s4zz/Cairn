import { unzipSync, strFromU8 } from "fflate";
import { describe, expect, it } from "vitest";

import { archiveDirectory } from "./sourceArchive";

function directoryFile(path: string, content: string): File {
  const file = new File([content], path.split("/").at(-1) || "source", { type: "text/plain" });
  Object.defineProperty(file, "webkitRelativePath", { value: path });
  Object.defineProperty(file, "arrayBuffer", { value: async () => new TextEncoder().encode(content).buffer });
  return file;
}

function blobBytes(blob: Blob): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(reader.error);
    reader.onload = () => resolve(new Uint8Array(reader.result as ArrayBuffer));
    reader.readAsArrayBuffer(blob);
  });
}

describe("archiveDirectory", () => {
  it("preserves browser directory paths in a valid ZIP", async () => {
    const result = await archiveDirectory([
      directoryFile("demo/src/main/java/App.java", "class App {}"),
      directoryFile("demo/pom.xml", "<project />"),
    ]);
    const files = unzipSync(await blobBytes(result));

    expect(result.name).toBe("demo.zip");
    expect(strFromU8(files["demo/src/main/java/App.java"])).toBe("class App {}");
    expect(strFromU8(files["demo/pom.xml"])).toBe("<project />");
  });

  it("rejects empty and traversing selections", async () => {
    await expect(archiveDirectory([])).rejects.toThrow("请选择包含源码的目录");
    await expect(archiveDirectory([directoryFile("demo/../secret.txt", "x")])).rejects.toThrow("不安全路径");
  });
});

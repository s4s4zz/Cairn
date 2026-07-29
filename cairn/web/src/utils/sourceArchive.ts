import { zip } from "fflate";

type DirectoryFile = File & { webkitRelativePath?: string };

function safePath(file: DirectoryFile): string {
  const candidate = (file.webkitRelativePath || file.name).replaceAll("\\", "/");
  const parts = candidate.split("/").filter(Boolean);
  if (!parts.length || candidate.startsWith("/") || parts.includes("..")) {
    throw new Error(`目录包含不安全路径：${candidate || file.name}`);
  }
  return parts.join("/");
}

export async function archiveDirectory(files: readonly File[]): Promise<File> {
  if (!files.length) throw new Error("请选择包含源码的目录");
  const entries: Record<string, Uint8Array> = {};
  for (const file of files) {
    const path = safePath(file as DirectoryFile);
    if (entries[path]) throw new Error(`目录包含重复路径：${path}`);
    entries[path] = new Uint8Array(await file.arrayBuffer());
  }
  const archive = await new Promise<Uint8Array>((resolve, reject) => {
    zip(entries, { level: 6 }, (error, data) => error ? reject(error) : resolve(data));
  });
  const root = safePath(files[0] as DirectoryFile).split("/")[0] || "source";
  return new File([archive], `${root}.zip`, { type: "application/zip" });
}

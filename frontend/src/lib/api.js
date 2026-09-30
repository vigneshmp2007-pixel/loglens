// Parse the response defensively: proxies / server crashes can return HTML or an empty body.
const json = async (r) => {
  let data = null;
  try { data = await r.json(); } catch { /* non-JSON body */ }
  if (!r.ok) throw new Error(data?.error || `Request failed (HTTP ${r.status})`);
  if (data === null) throw new Error("Server returned an invalid response");
  return data;
};

const request = async (url, options) => {
  try {
    return json(await fetch(url, options));
  } catch (e) {
    if (e instanceof TypeError) throw new Error("Cannot reach the API. Is the backend running on port 5000?");
    throw e;
  }
};

export async function analyzeFile(file) {
  const f = new FormData();
  f.append("file", file);
  return request("/api/analyze", { method: "POST", body: f });
}
export async function loadDemo() { return request("/api/demo", { method: "POST" }); }
export async function getHealth() { return request("/api/health"); }

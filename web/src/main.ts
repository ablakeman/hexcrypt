import "@fontsource-variable/recursive/mono.css";
import init, * as hc from "./wasm/hexcrypt_core.js";

const app = document.getElementById("app")!;
const ID_RE = /^\/([0-9a-f]{12})\/?$/;
const EXPIRIES: [string, number][] = [["1 hour", 3600], ["1 day", 86400], ["7 days", 604800]];
const calm = matchMedia("(prefers-reduced-motion: reduce)");

const el = <K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Record<string, string> = {}, ...kids: (Node | string)[]) => {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) k === "class" ? (e.className = v) : e.setAttribute(k, v);
  e.append(...kids);
  return e;
};
const button = (cls: string, label: string) => el("button", { class: cls, type: "button" }, label) as HTMLButtonElement;
const fmtSize = (n: number) => (n < 1024 ? `${n} bytes` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function frame(intro: Node[], panel: Node, after: Node[] = []) {
  app.replaceChildren(
    el("header", { class: "top" },
      el("a", { class: "brand", href: "/" }, el("img", { src: "/favicon.svg", alt: "", width: "24", height: "24" }), "hexcrypt"),
      el("a", { href: "https://github.com/ablakeman/hexcrypt" }, "Source"),
    ),
    el("main", { class: "stage" }, el("div", { class: "intro" }, ...intro), panel),
    ...after,
    el("footer", {}, "Open source, MIT licensed. Run your own with ", el("code", {}, "hexcrypt serve"), "."),
  );
}

/** xxd-style rows: what the server actually stores. */
function hexRows(bytes: Uint8Array, maxRows = 8): string[] {
  const per = matchMedia("(max-width: 560px)").matches ? 8 : 16;
  const rows: string[] = [];
  for (let off = 0; off < bytes.length && rows.length < maxRows; off += per) {
    const hex = Array.from(bytes.subarray(off, off + per), (b) => b.toString(16).padStart(2, "0")).join("");
    rows.push(`${off.toString(16).padStart(8, "0")}  ${hex.match(/.{1,4}/g)!.join(" ")}`);
  }
  const rest = bytes.length - Math.min(bytes.length, per * maxRows);
  if (rest > 0) rows.push(`… ${rest.toLocaleString()} more bytes`);
  return rows;
}

/** Print rows one at a time, like a terminal. The page's one piece of motion. */
async function stream(pre: HTMLElement, rows: string[]) {
  if (calm.matches) { pre.textContent = rows.join("\n"); return; }
  pre.textContent = "";
  for (const r of rows) { pre.textContent += (pre.textContent ? "\n" : "") + r; await sleep(45); }
}

/** A link split at the #: the part the server sees and the part it never does. */
function anatomy(url: string) {
  const i = url.indexOf("#");
  const seg = (cls: string, text: string, cap: string) =>
    el("span", { class: `seg ${cls}` }, el("code", {}, text), el("span", { class: "cap" }, cap));
  return el("div", { class: "anatomy" },
    seg("where", url.slice(0, i), "Sent to the server, to say which secret to fetch."),
    seg("key", url.slice(i), "Never sent. Browsers keep the part after # to themselves, and it decrypts the secret."),
  );
}

async function createView() {
  let maxSize = 1024 * 1024, maxExpiry = 86400;
  try { ({ max_size: maxSize = maxSize, max_expiry: maxExpiry = maxExpiry } = await (await fetch("/api/v1/config")).json()); } catch {}

  const ta = el("textarea", { placeholder: "Paste a password, API token, .env file or private note", spellcheck: "false", autofocus: "", "aria-label": "Secret" }) as HTMLTextAreaElement;
  const fileInput = el("input", { type: "file", "aria-label": "File" }) as HTMLInputElement;
  const dropText = el("div", {}, el("strong", {}, "Choose a file"), " or drop it here");
  const drop = el("div", { class: "drop", hidden: "" }, dropText, fileInput);
  const tabText = el("button", { type: "button", role: "tab", "aria-selected": "true" }, "Text");
  const tabFile = el("button", { type: "button", role: "tab", "aria-selected": "false" }, "File");
  const select = el("select", {}) as HTMLSelectElement;
  for (const [label, secs] of EXPIRIES) if (secs <= maxExpiry) select.append(el("option", { value: String(secs) }, label));
  select.value = String(Math.min(86400, maxExpiry));
  const go = button("btn", "Create link");
  const err = el("p", { class: "err", role: "alert" });
  const panel = el("section", { class: "panel", "aria-label": "New secret" },
    el("div", { class: "panel-bar" }, el("div", { class: "tabs", role: "tablist" }, tabText, tabFile), el("span", {}, `Up to ${fmtSize(maxSize)}`)),
    el("div", { class: "panel-body" }, ta, drop),
    el("div", { class: "panel-foot" }, el("label", { class: "inline" }, "Expires after", select), go),
    err,
  );

  let mode: "text" | "file" = "text";
  const setMode = (m: typeof mode) => {
    mode = m;
    ta.hidden = m !== "text";
    drop.hidden = m !== "file";
    tabText.setAttribute("aria-selected", String(m === "text"));
    tabFile.setAttribute("aria-selected", String(m === "file"));
  };
  tabText.onclick = () => setMode("text");
  tabFile.onclick = () => setMode("file");
  fileInput.onchange = () => {
    const f = fileInput.files?.[0];
    dropText.replaceChildren(...(f ? [el("strong", {}, f.name), `, ${fmtSize(f.size)}`] : [el("strong", {}, "Choose a file"), " or drop it here"]));
  };
  drop.ondragover = (e) => { e.preventDefault(); drop.classList.add("over"); };
  drop.ondragleave = () => drop.classList.remove("over");
  drop.ondrop = (e) => {
    e.preventDefault(); drop.classList.remove("over");
    if (e.dataTransfer?.files.length) { fileInput.files = e.dataTransfer.files; fileInput.onchange!(new Event("change")); }
  };

  const h1 = el("h1", {}, "Share a secret once.");
  const lede = el("p", { class: "lede" }, "Encrypted on your device. You hold the key, not us.");
  const cli = el("div", { class: "cli" }, el("p", {}, "Or from a terminal:"), el("pre", {}, "$ cargo install hexcrypt-cli\n$ hexcrypt send .env"));
  const sample = `${location.origin}/${hc.new_id()}#${hc.encode_key(hc.new_key())}`;
  const explain = el("section", { class: "explain" },
    el("h2", {}, "What's in a link"),
    anatomy(sample),
    el("p", {}, "The first person to open the link gets the secret. Reading it deletes the stored copy in the same step, so a second visit finds nothing. Unopened secrets are deleted when they expire."),
  );

  go.onclick = async () => {
    err.textContent = "";
    let kind = 0, name = "", data: Uint8Array;
    if (mode === "text") {
      if (!ta.value) { err.textContent = "Type or paste something to share first."; ta.focus(); return; }
      data = new TextEncoder().encode(ta.value);
    } else {
      const f = fileInput.files?.[0];
      if (!f) { err.textContent = "Choose a file to share first."; return; }
      kind = 1; name = f.name; data = new Uint8Array(await f.arrayBuffer());
    }
    if (data.length + 64 > maxSize) { err.textContent = `That's ${fmtSize(data.length)}. This server takes up to ${fmtSize(maxSize)}.`; return; }
    go.disabled = true; go.textContent = "Encrypting…";
    try {
      const id = hc.new_id();
      const key = hc.new_key();
      const blob = hc.encrypt(id, key, kind, name, data);
      go.textContent = "Uploading…";
      const res = await fetch(`/api/v1/secrets/${id}`, { method: "PUT", headers: { "x-expires-seconds": select.value }, body: blob as BodyInit });
      if (!res.ok) {
        throw new Error(res.status === 413 ? `Too large for this server. The limit is ${fmtSize(maxSize)}.`
          : res.status === 429 ? "You've hit this server's upload limit. Try again later."
          : `The server returned an error (${res.status}). Try again.`);
      }
      // The key goes in the fragment; browsers never send it to the server.
      const url = `${location.origin}/${id}#${hc.encode_key(key)}`;
      h1.textContent = "Your link is ready.";
      lede.textContent = "Send it over a channel you trust. Whoever opens it first gets the secret. Chat apps that preview links don't open it; only pressing Reveal does.";
      cli.remove(); explain.remove();
      showLink(panel, blob, url, select.selectedOptions[0].text);
    } catch (e) {
      err.textContent = String((e as Error).message ?? e);
      go.disabled = false; go.textContent = "Create link";
    }
  };

  frame([h1, lede, cli], panel, [explain]);
}

function showLink(panel: HTMLElement, blob: Uint8Array, url: string, expiry: string) {
  const dump = el("pre", { class: "dump", "aria-label": "Ciphertext as stored on the server" });
  const copy = button("btn", "Copy link");
  const again = button("btn quiet", "Share another secret");
  const note = el("p", { class: "note", role: "status" }, `Opens once. Deleted in ${expiry} if nobody opens it.`);
  copy.onclick = async () => {
    try { await navigator.clipboard.writeText(url); copy.textContent = "Copied"; setTimeout(() => (copy.textContent = "Copy link"), 1600); }
    catch { note.textContent = "The clipboard isn't available here. Select the link above and copy it."; }
  };
  again.onclick = () => createView();
  panel.setAttribute("aria-label", "Your link");
  panel.replaceChildren(
    el("div", { class: "panel-bar" }, el("span", {}, "Encrypted. This is all the server stores."), el("span", {}, fmtSize(blob.length))),
    el("div", { class: "panel-body sealed" }, dump),
    el("div", { class: "panel-link" }, anatomy(url)),
    el("div", { class: "panel-foot" }, again, copy),
    note,
  );
  copy.focus();
  stream(dump, hexRows(blob));
}

function revealView(id: string) {
  const keyStr = location.hash.slice(1);
  const reveal = button("btn", "Reveal secret");
  const err = el("p", { class: "err", role: "alert" });
  const state = el("span", {}, "Sealed");
  const msg = el("p", { class: "sealed-msg" }, "Revealing decrypts it on this device and deletes the server copy.");
  const body = el("div", { class: "panel-body sealed" }, msg);
  const foot = el("div", { class: "panel-foot" }, el("span", { class: "note" }, "Have somewhere ready to paste or save it."), reveal);
  const panel = el("section", { class: "panel", "aria-label": "Secret" },
    el("div", { class: "panel-bar" }, state, el("code", {}, id)), body, foot, err);

  if (!keyStr) {
    foot.hidden = true;
    msg.textContent = "This link is missing its key, the part after #. Ask the sender to copy the whole link.";
  }

  reveal.onclick = async () => {
    reveal.disabled = true; reveal.textContent = "Revealing…"; err.textContent = "";
    try {
      const key = hc.decode_key(keyStr);
      const res = await fetch(`/api/v1/secrets/${id}`, { cache: "no-store" });
      if (res.status === 404) {
        state.textContent = "Gone";
        msg.textContent = "Nothing to reveal. This secret was already opened, has expired, or the link is incomplete.";
        foot.hidden = true;
        return;
      }
      if (!res.ok) throw new Error(`The server returned an error (${res.status}). Try again.`);
      const blob = new Uint8Array(await res.arrayBuffer());
      const opened = hc.decrypt(id, key, blob);
      const dump = el("pre", { class: "dump" });
      body.replaceChildren(dump);
      await stream(dump, hexRows(blob));
      if (!calm.matches) await sleep(300);

      body.classList.remove("sealed");
      state.textContent = "Revealed. The server copy is deleted.";
      let action: HTMLElement;
      if (opened.kind === 0) {
        const text = new TextDecoder().decode(opened.data);
        body.replaceChildren(el("pre", { class: "secret" }, text));
        const copy = button("btn", "Copy");
        copy.onclick = async () => {
          try { await navigator.clipboard.writeText(text); copy.textContent = "Copied"; }
          catch { err.textContent = "The clipboard isn't available here. Select the text and copy it."; }
        };
        action = copy;
      } else {
        const name = opened.name || "secret";
        body.replaceChildren(el("div", { class: "file" }, el("code", {}, name), el("span", {}, fmtSize(opened.data.length))));
        action = el("a", { class: "btn", href: URL.createObjectURL(new Blob([opened.data as BlobPart])), download: name }, "Download");
      }
      foot.replaceChildren(el("span", { class: "note" }, "This is the only copy now. Save it before you leave."), action);
      action.focus();
    } catch (e) {
      err.textContent = String((e as Error).message ?? e);
      reveal.disabled = false; reveal.textContent = "Reveal secret";
    }
  };

  frame([
    el("h1", {}, "Someone sent you a secret."),
    el("p", { class: "lede" }, "It can be opened once. The key is in this link, so it's decrypted here in your browser, not on the server."),
  ], panel);
}

(async () => {
  try {
    await init();
  } catch (e) {
    app.replaceChildren(el("p", { class: "err" }, "The encryption module didn't load, so nothing can be encrypted here. Reload the page to try again. " + String(e)));
    return;
  }
  const m = location.pathname.match(ID_RE);
  if (m) revealView(m[1]); else createView();
})();

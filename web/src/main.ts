import init, * as hc from "./wasm/hexcrypt_core.js";

const app = document.getElementById("app")!;
const ID_RE = /^\/([0-9a-f]{12})\/?$/;
const EXPIRIES: [string, number][] = [["1 hour", 3600], ["1 day", 86400], ["7 days", 604800]];

const el = <K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Record<string, string> = {}, ...kids: (Node | string)[]) => {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) k === "class" ? (e.className = v) : e.setAttribute(k, v);
  e.append(...kids);
  return e;
};
const fmtSize = (n: number) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`);

function frame(...content: Node[]) {
  const brand = el("a", { class: "brand", href: "/" }, el("img", { src: "/favicon.svg", alt: "" }), el("span", {}, "hexcrypt"));
  app.replaceChildren(
    el("header", { class: "top" }, brand),
    ...content,
    el("footer", {},
      el("span", {}, "Zero-knowledge. Encrypted in your browser; the server only ever sees ciphertext."),
      el("a", { href: "https://github.com/ablakeman/hexcrypt" }, "Source"),
      el("span", {}, "CLI: ", el("code", {}, "cargo install hexcrypt-cli")),
    ),
  );
}

async function createView() {
  let maxSize = 10 * 1024 * 1024;
  try { maxSize = (await (await fetch("/api/v1/config")).json()).max_size ?? maxSize; } catch {}

  const ta = el("textarea", { placeholder: "Paste a password, token, .env, private note…", spellcheck: "false", autofocus: "" }) as HTMLTextAreaElement;
  const fileInput = el("input", { type: "file" }) as HTMLInputElement;
  const dropText = el("div", {}, el("strong", {}, "Choose a file"), ` or drop it here · up to ${fmtSize(maxSize)}`);
  const drop = el("div", { class: "drop", hidden: "" }, dropText, fileInput);
  const tabText = el("button", { type: "button", role: "tab", "aria-selected": "true" }, "Text");
  const tabFile = el("button", { type: "button", role: "tab", "aria-selected": "false" }, "File");
  const select = el("select", { "aria-label": "Expires after" }) as HTMLSelectElement;
  for (const [label, secs] of EXPIRIES) select.append(el("option", { value: String(secs) }, label));
  select.value = "86400";
  const go = el("button", { class: "btn big", type: "button" }, "Encrypt & create link") as HTMLButtonElement;
  const err = el("p", { class: "err" });
  const card = el("div", { class: "card" },
    el("div", { class: "tabs", role: "tablist" }, tabText, tabFile),
    ta, drop,
    el("div", { class: "row" }, el("label", { class: "inline" }, "Expires after", select)),
    el("div", { class: "row" }, go),
    err,
    el("p", { class: "hint" }, "The link opens ", el("b", {}, "once"), ". After that, or after it expires, the secret is gone from the server for good."),
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
    dropText.replaceChildren(f ? el("strong", {}, f.name) : el("strong", {}, "Choose a file"), f ? ` · ${fmtSize(f.size)}` : " or drop it here");
  };
  drop.ondragover = (e) => { e.preventDefault(); drop.classList.add("over"); };
  drop.ondragleave = () => drop.classList.remove("over");
  drop.ondrop = (e) => {
    e.preventDefault(); drop.classList.remove("over");
    if (e.dataTransfer?.files.length) { fileInput.files = e.dataTransfer.files; fileInput.onchange!(new Event("change")); }
  };

  go.onclick = async () => {
    err.textContent = "";
    let kind = 0, name = "", data: Uint8Array;
    if (mode === "text") {
      if (!ta.value) { err.textContent = "Nothing to encrypt."; return; }
      data = new TextEncoder().encode(ta.value);
    } else {
      const f = fileInput.files?.[0];
      if (!f) { err.textContent = "Pick a file first."; return; }
      kind = 1; name = f.name; data = new Uint8Array(await f.arrayBuffer());
    }
    if (data.length + 64 > maxSize) { err.textContent = `Too large. Limit is ${fmtSize(maxSize)}.`; return; }
    go.disabled = true; go.textContent = "Encrypting…";
    try {
      const id = hc.new_id();
      const key = hc.new_key();
      const blob = hc.encrypt(id, key, kind, name, data);
      go.textContent = "Uploading…";
      const res = await fetch(`/api/v1/secrets/${id}`, { method: "PUT", headers: { "x-expires-seconds": select.value }, body: blob as BodyInit });
      if (!res.ok) throw new Error(`Server said ${res.status}: ${await res.text()}`);
      // The key goes in the fragment; browsers never send it to the server.
      const url = `${location.origin}/${id}#${hc.encode_key(key)}`;
      resultView(url, select.selectedOptions[0].text);
    } catch (e) {
      err.textContent = String((e as Error).message ?? e);
      go.disabled = false; go.textContent = "Encrypt & create link";
    }
  };

  frame(
    el("h1", {}, "Share a secret once."),
    el("p", { class: "lede" }, "Encrypted in your browser before upload. The key lives only in the link you send. We can't read it, and neither can anyone without the link."),
    card,
    el("section", { class: "how" },
      el("div", {}, el("b", {}, "1. Encrypt here"), "XChaCha20-Poly1305 runs in your browser via WebAssembly. Plaintext never leaves your device."),
      el("div", {}, el("b", {}, "2. Send the link"), "The key is after the # in the URL. Browsers never send that part to any server."),
      el("div", {}, el("b", {}, "3. Read once"), "The first open deletes the ciphertext. Expired secrets are purged automatically."),
    ),
  );
}

function resultView(url: string, expiry: string) {
  const input = el("input", { type: "text", readonly: "", value: url, "aria-label": "Secret link" }) as HTMLInputElement;
  const copy = el("button", { class: "btn", type: "button" }, "Copy") as HTMLButtonElement;
  copy.onclick = async () => {
    try { await navigator.clipboard.writeText(url); copy.textContent = "Copied"; setTimeout(() => (copy.textContent = "Copy"), 1500); }
    catch { input.select(); }
  };
  const again = el("button", { class: "btn ghost", type: "button" }, "Create another") as HTMLButtonElement;
  again.onclick = () => createView();
  frame(
    el("h1", {}, "Your one-time link"),
    el("p", { class: "lede" }, `Opens once, then it's gone. Expires in ${expiry} if never opened.`),
    el("div", { class: "card" },
      el("div", { class: "link" }, input, copy),
      el("p", { class: "hint" }, "Send this over a channel you trust. Anyone who opens it first gets the secret. Link previews from chat apps do not burn it; only clicking Reveal does."),
      el("div", { class: "row" }, again),
    ),
  );
  input.focus(); input.select();
}

function revealView(id: string) {
  const keyStr = location.hash.slice(1);
  const err = el("p", { class: "err" });
  const reveal = el("button", { class: "btn big", type: "button" }, "Reveal secret") as HTMLButtonElement;
  const body = el("div", {});
  const card = el("div", { class: "card" }, body, reveal, err,
    el("p", { class: "hint" }, "This can be viewed ", el("b", {}, "once"), ". Revealing it deletes it from the server. Make sure you're ready to copy or save it."));

  if (!keyStr) {
    reveal.hidden = true;
    err.textContent = "This link is missing its key (the part after #). Ask the sender to resend the full link.";
  }

  reveal.onclick = async () => {
    reveal.disabled = true; reveal.textContent = "Fetching…"; err.textContent = "";
    try {
      const key = hc.decode_key(keyStr);
      const res = await fetch(`/api/v1/secrets/${id}`, { cache: "no-store" });
      if (res.status === 404) throw new Error("This secret is gone. It was already opened, it expired, or it never existed.");
      if (!res.ok) throw new Error(`Server said ${res.status}`);
      const blob = new Uint8Array(await res.arrayBuffer());
      const opened = hc.decrypt(id, key, blob);
      reveal.hidden = true;
      if (opened.kind === 0) {
        const text = new TextDecoder().decode(opened.data);
        const copy = el("button", { class: "btn", type: "button" }, "Copy") as HTMLButtonElement;
        copy.onclick = async () => { try { await navigator.clipboard.writeText(text); copy.textContent = "Copied"; } catch {} };
        body.replaceChildren(el("pre", { class: "secret" }, text), el("div", { class: "row" }, copy));
      } else {
        const data = opened.data;
        const dl = URL.createObjectURL(new Blob([data as BlobPart]));
        const a = el("a", { class: "btn", href: dl, download: opened.name || "secret" }, "Download");
        body.replaceChildren(el("div", { class: "file" },
          el("div", {}, el("div", { class: "name" }, opened.name || "secret"), el("div", { class: "size" }, fmtSize(data.length))), a));
      }
      card.querySelector(".hint")!.textContent = "Decrypted locally. This secret no longer exists on the server; save it now if you need it.";
    } catch (e) {
      err.textContent = String((e as Error).message ?? e);
      reveal.disabled = false; reveal.textContent = "Reveal secret";
    }
  };

  frame(
    el("h1", {}, "Someone sent you a secret."),
    el("p", { class: "lede" }, "It's encrypted. Decryption happens in your browser using the key in this link."),
    card,
  );
}

(async () => {
  try {
    await init();
  } catch (e) {
    app.replaceChildren(el("p", { class: "err" }, "Could not load the encryption module. " + String(e)));
    return;
  }
  const m = location.pathname.match(ID_RE);
  if (m) revealView(m[1]); else createView();
})();

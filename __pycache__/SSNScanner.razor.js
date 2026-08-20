/*
 * SSN Scanner — collocated JS module.
 *
 * Loaded by SSNScanner.razor in OnAfterRenderAsync from
 * ./Components/Pages/SSNScanner/SSNScanner.razor.js
 *
 * Deliberately tiny. Only two things genuinely need the browser: the
 * clipboard, and handing a generated file to the user. Everything else,
 * including all detection and all redaction, happens in C# on the server, so
 * no SSN ever exists as JavaScript data.
 */

/**
 * Copies text to the clipboard.
 *
 * navigator.clipboard requires a secure context. Plain http://localhost counts
 * as one, but an intranet http:// origin does not, so the textarea fallback is
 * load-bearing rather than legacy-browser politeness.
 *
 * @param {string} text
 * @returns {Promise<boolean>} whether the copy appeared to succeed
 */
export async function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
        try {
            await navigator.clipboard.writeText(text);
            return true;
        } catch {
            // fall through to the manual path below
        }
    }

    const scratch = document.createElement("textarea");
    scratch.value = text;
    scratch.setAttribute("readonly", "");
    scratch.style.position = "fixed";
    scratch.style.opacity = "0";
    document.body.appendChild(scratch);

    try {
        scratch.select();
        return document.execCommand("copy");
    } catch {
        return false;
    } finally {
        // clear the element's own copy before it leaves the DOM
        scratch.value = "";
        document.body.removeChild(scratch);
    }
}

/**
 * Triggers a download of text generated on the server.
 *
 * The object URL is revoked immediately after the click so the blob is not
 * left reachable from the page.
 *
 * @param {string} filename
 * @param {string} mimeType
 * @param {string} content
 */
export function downloadText(filename, mimeType, content) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);

    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    link.style.display = "none";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

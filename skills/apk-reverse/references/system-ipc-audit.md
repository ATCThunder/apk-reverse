# System IPC audit — Binder, Intent, WebView, SELinux, attestation

Load this when the question is not "what code does the app run" but **"what does the app ask the
system to do, and who answers"**: you need to see the app's Binder traffic to a system service,
decide whether a behaviour is decided by an Intent/JS-bridge input you can control, understand a
`service call` transaction code, get past an `avc: denied` that is blocking your instrumentation,
or reason about a Keystore attestation check that is flagging your rooted device. This file is the
system-side complement to `references/dynamic-frida.md` §Hook strategy (in-process observation) and
`references/protocol-reverse.md` (the app's own network wire): those own the app's traffic, this one
owns the platform boundary it talks to.

**Strength note, read this first:** nothing in this file was run end to end by this repository's
verification passes — no Binder hook, no `service call` probe, no attestation parse was executed
against a sample here. The commands and hook scripts are absorbed from an external notes site
(milksu.org, Android internals notes, retrieved 2026-10-19) and are **unverified** in the sense of
`references/coverage-and-limits.md` §Strength labels: reported by someone else, not reproduced here.
The platform *mechanisms* they rest on — AIDL codegen arithmetic, `FIRST_CALL_TRANSACTION`,
kernel-filled caller identity, `FLAG_IMMUTABLE` being mandatory since Android 12, the attestation
extension fields — are **inferred**: they follow from documented AOSP behaviour the notes cite, and
each is the kind of fact that fails loudly if wrong (a wrong transaction code returns an error, not
a silent miss). Treat the scripts as starting points to verify on your own device, not as measured
procedures, and label your own results the same way.

## 1. Binder — seeing the app's calls into system_server

The app's privileged actions (install, start components, clipboard, location) cross the Binder
boundary, and the *server* side re-checks identity there: `Binder.getCallingUid()/getCallingPid()`
is filled in by the binder driver from the calling task, **not** copied from the parcel, so it is
not spoofable from the client side (inferred from the driver's documented behaviour). Two practical
consequences: you cannot fake another app's UID by crafting a parcel, and when you hook a system
service's entry the UID you see is the truth about who called.

**Transaction codes.** AIDL generates `TRANSACTION_<method> = FIRST_CALL_TRANSACTION + n` with
`FIRST_CALL_TRANSACTION = 1` and `n` the method's 0-based ordinal in the `.aidl` file (inferred
from the codegen contract). So "the 5th method in `IFoo.aidl`" is code `5`. Version drift changes
ordinals — recompute against the `.aidl` or the generated Stub of the Android release you are on
before trusting a numeric code.

**Observing outbound traffic (client side, in the target app's process):**

```javascript
// unverified — absorbed from milksu.org notes, not run by this repo
Java.perform(function() {
    var BP = Java.use("android.os.BinderProxy");
    BP.transact.implementation = function(code, data, reply, flags) {
        console.log("[Binder] " + this.getInterfaceDescriptor() + " code=" + code);
        return this.transact(code, data, reply, flags);
    };
});
```

`getInterfaceDescriptor()` names the service, `code` names the method — together they are the
"which privileged call, with which arguments" record that static analysis of the app alone cannot
give you when the call site is behind a SDK facade. For inbound traffic (something calling *into*
the app — an exported service, a callback interface), hook `android.os.Binder.execTransact` the
same way.

**Driving a service by hand:** `adb shell service list` enumerates services;
`adb shell service call <service> <code> i32 ... s16 ...` invokes transaction `<code>` directly
(`i32`/`i64`/`f`/`d`/`s16` are the argument type tags). Use it to confirm a code number against a
known method before you build a hook on it. `adb shell dumpsys binder_calls_stats` (Android 9+)
shows which binder calls a process actually made — a zero-friction first look before you hook
anything.

## 2. Intent audit — the input channels a repack cannot remove

The app's exported components and deep links are inputs an attacker (and you, when testing) control
without repacking. Three signatures worth grepping a jadx export for, all unverified as to
prevalence but mechanically cheap to check:

| Signature | Meaning |
|---|---|
| `getParcelableExtra("intent"\|"next"\|"redirect"\|"forward")` fed straight to `startActivity`/`sendBroadcast` | Intent redirection: your crafted nested Intent runs with this app's identity and privileges |
| implicit `Intent` sent with sensitive extras and no `setPackage()` | any higher-priority receiver can register for the action and harvest the extras |
| deep link / Intent extra flowing into `loadUrl` or a file path without scheme/host whitelist | injection into the WebView or path traversal surface (next section) |

`PendingIntent` without `FLAG_IMMUTABLE` (mandatory to *declare* either flag since Android 12 —
inferred from the platform change) is the same class of bug with a capability token: a mutable
PendingIntent handed to an untrusted party lets them rewrite the inner Intent.

## 3. WebView and the JS bridge — audit surface, not attack surface

For reverse engineering the interesting facts are configuration and bridge inventory, both readable
statically (grep a jadx export) and dynamically (hook the registration):

```javascript
// unverified — absorbed from milksu.org notes, not run by this repo
var WV = Java.use('android.webkit.WebView');
WV.addJavascriptInterface.implementation = function(obj, name) {
    console.log('[WV] bridge: ' + name + ' -> ' + obj.getClass().getName());
    var ms = obj.getClass().getDeclaredMethods();
    for (var i = 0; i < ms.length; i++) console.log('   ' + ms[i].getName());
    return this.addJavascriptInterface(obj, name);
};
```

Settings that widen what web content can reach, in descending order of risk:

| Setting | Effect if `true` |
|---|---|
| `setAllowUniversalAccessFromFileURLs` | a `file://` page can read any origin — the app's private files included |
| `setAllowFileAccessFromFileURLs` | `file://` pages can read other `file://` URLs |
| `setAllowFileAccess` / `setAllowContentAccess` | `file://` / `content://` loadable at all |
| `setWebContentsDebuggingEnabled` | **in production: a free remote-debug entry for you** — `adb forward tcp:9222 localabstract:webview_devtools_remote_<pid>` then `chrome://inspect`, no root needed |

A `file://` deep link plus the first two settings is the classic private-data-exfiltration chain:
drop an HTML file, get it opened, read `/data/data/<pkg>/…` from JS. When the app's logic you are
chasing lives behind a JS bridge method (`window.android.foo()`), the hook above names the Java
class; from there it is an ordinary Java-layer hook, not a web problem.

## 4. SELinux — when it blocks *your* tools, not the app

`avc: denied` lines in logcat/dmesg carry four useful fields: `scontext` (who), `tcontext` (what),
`tclass` (class), and the requested permission. When frida-server or a pushed binary will not run,
this is the usual cause — the file's context does not permit execution from the domain that tried.
The notes' remediation sequence, unverified here: read the denial, then either relabel/relocate the
binary, or generate the exact allow rule with `adb shell dmesg | audit2allow -p sepolicy.bin` after
pulling the policy from `/sys/fs/selinux/policy`, and audit what it emits before applying it
(`audit2allow` is deliberately over-broad). For *reading* what an app domain may do,
`sesearch -A -s untrusted_app sepolicy.bin` answers "can this app even reach X" questions that
save a hook that could never fire.

## 5. Keystore attestation — the check that survives client-side patching

Key attestation returns a certificate chain (Google root → device key → per-key cert) whose
extension records `verifiedBootState`, `deviceLocked`, and the security level (Software / TEE /
StrongBox). An app that ships this and *verifies it server-side* has a root/bootloader-unlock
detector you cannot satisfy by patching the client — the honest routes are a device that passes,
or finding the server-side decision and what it actually gates. What you *can* observe client-side:
hook `android.security.keystore.KeyGenParameterSpec$Builder.build` and
`java.security.KeyStore.getEntry` to see aliases, purposes, and whether user-auth binding is
requested — that tells you whether the app leans on hardware keys at all before you spend time on
the harder question. This is the boundary case for
`references/detection-and-anti-analysis.md` §Step 3: locating the check — the order of search: the
check runs outside the process, so in-process stages cannot reach it.

## 6. Where this hands off

- App's own network traffic (the wire, not the platform): `references/protocol-reverse.md`
- TLS/certificate failures on one feature: `references/tls-and-cert.md` §If OkHttp is the failing path
- Hooking environment and strategy: `references/dynamic-frida.md` §Hook strategy
- Detection that fires before your hooks exist: `references/detection-and-anti-analysis.md` §Step 3: locating the check — the order of search

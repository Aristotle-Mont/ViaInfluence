/**
 * server.js — LOCAL ADMIN SCRIPT, NOT A HOSTED SERVER
 * ============================================================
 * GitHub Pages only serves static files (index.html, css, js) — it cannot
 * run Node, so this file is never deployed there. Instead, you run this
 * on YOUR OWN MACHINE whenever you want to invite a new creator. It's the
 * actual access-control gate behind "no public signup": it's the only
 * piece of code in this whole project that's allowed to grant the
 * `role: "creator"` custom claim, and it requires a secret key that never
 * leaves your computer.
 *
 * USAGE:
 *   node server.js invite "sarah@example.com" "Sarah Eats"
 *
 * WHAT IT DOES:
 *   1. Creates (or finds) a Firebase Auth user for that email
 *   2. Sets the custom claim { role: "creator" } on that account —
 *      this is the claim your Firestore/Storage rules check on every
 *      read/write, and the ONLY way to set it is via this Admin SDK script
 *   3. Creates a matching /creators/{uid} Firestore profile document
 *   4. Prints a temporary password for you to hand off securely (Signal,
 *      not email/Slack) — the creator should change it on first login
 * ============================================================
 */

const admin = require("firebase-admin");
const crypto = require("crypto");

// ------------------------------------------------------------------
// SECRET HANDLING — this is the part that actually needs protecting.
// The service account key grants FULL admin access to your Firebase
// project (bypasses all security rules). Treat it like a master password:
//   - Never commit it to git (see .gitignore below)
//   - Never put it in the index.html / anything that ships to the browser
//   - Load it from an environment variable, not a hardcoded path
//
// Setup:
//   1. Firebase Console → Project Settings → Service Accounts →
//      "Generate new private key" → downloads a .json file
//   2. Save it OUTSIDE your git repo, e.g. ~/secrets/viadice-service-account.json
//   3. Set an environment variable pointing to it:
//        macOS/Linux:  export GOOGLE_APPLICATION_CREDENTIALS="$HOME/secrets/viadice-service-account.json"
//        Windows (PowerShell): $env:GOOGLE_APPLICATION_CREDENTIALS="C:\secrets\viadice-service-account.json"
//   4. Re-run that export command in any new terminal session (or add it
//      to your shell profile ~/.zshrc / ~/.bashrc so it persists)
// ------------------------------------------------------------------

if (!process.env.GOOGLE_APPLICATION_CREDENTIALS) {
  console.error(
    "\n✗ GOOGLE_APPLICATION_CREDENTIALS is not set.\n" +
    "  This script needs your Firebase service account key to run.\n" +
    "  See the setup comment at the top of this file.\n"
  );
  process.exit(1);
}

admin.initializeApp({
  credential: admin.credential.applicationDefault()
});

const auth = admin.auth();
const db = admin.firestore();

function generateTempPassword() {
  // 16 random bytes → base64, trimmed to a clean 16-char string.
  // Strong enough for a one-time temp password the creator changes immediately.
  return crypto.randomBytes(16).toString("base64").replace(/[^a-zA-Z0-9]/g, "").slice(0, 16);
}

async function inviteCreator(email, displayName) {
  if (!email || !displayName) {
    console.error("Usage: node server.js invite \"email@example.com\" \"Display Name\"");
    process.exit(1);
  }

  // Basic shape check — not a substitute for real email verification,
  // just stops obvious typos before we create an account.
  const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailPattern.test(email)) {
    console.error("✗ That doesn't look like a valid email address.");
    process.exit(1);
  }

  let userRecord;
  const tempPassword = generateTempPassword();

  try {
    // Does this email already have an account?
    userRecord = await auth.getUserByEmail(email);
    console.log(`User already exists (${userRecord.uid}) — updating role claim only.`);
  } catch (err) {
    if (err.code === "auth/user-not-found") {
      userRecord = await auth.createUser({
        email,
        password: tempPassword,
        displayName,
        emailVerified: false
      });
      console.log(`Created new Auth user: ${userRecord.uid}`);
    } else {
      throw err;
    }
  }

  // ---- The actual access-control gate ----
  await auth.setCustomUserClaims(userRecord.uid, { role: "creator" });
  console.log(`Set role:"creator" claim on ${userRecord.uid}`);

  // ---- Matching Firestore profile (public-readable card info) ----
  await db.collection("creators").doc(userRecord.uid).set(
    {
      displayName,
      followerCount: 0,
      viewsThisMonth: 0,
      saveCount: 0,
      verified: false,
      status: "active",
      invitedAt: admin.firestore.FieldValue.serverTimestamp()
    },
    { merge: true }
  );
  console.log(`Created /creators/${userRecord.uid} profile document.`);

  console.log("\n✓ Invite complete.");
  console.log(`  Email:            ${email}`);
  console.log(`  Temp password:    ${tempPassword}`);
  console.log(`  Hand this password to ${displayName} over a secure channel`);
  console.log(`  (Signal, in person — not email or Slack). They should sign in`);
  console.log(`  once and you should prompt them to reset it immediately —`);
  console.log(`  add a "change password" flow in the portal before onboarding`);
  console.log(`  real creators.\n`);
}

async function revokeCreator(email) {
  const userRecord = await auth.getUserByEmail(email);
  await auth.setCustomUserClaims(userRecord.uid, { role: null });
  await db.collection("creators").doc(userRecord.uid).update({ status: "suspended" });
  console.log(`✓ Revoked creator access for ${email} (${userRecord.uid})`);
}

// ------------------------------------------------------------------
// CLI entry point
// ------------------------------------------------------------------
const [, , command, ...args] = process.argv;

(async () => {
  try {
    if (command === "invite") {
      await inviteCreator(args[0], args[1]);
    } else if (command === "revoke") {
      await revokeCreator(args[0]);
    } else {
      console.log(
        "Usage:\n" +
        '  node server.js invite "email@example.com" "Display Name"\n' +
        '  node server.js revoke "email@example.com"\n'
      );
    }
  } catch (err) {
    console.error("✗ Error:", err.message);
    process.exit(1);
  }
  process.exit(0);
})();
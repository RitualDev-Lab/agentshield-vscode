import * as vscode from "vscode";

// High-speed ReDoS-safe patterns for real-time IDE diagnostics
const SECRET_DETECTORS = [
  { id: "OPENAI_KEY", name: "OpenAI Secret Key", regex: /\b(sk-[a-zA-Z0-9]{20,64})\b/g },
  { id: "AWS_ACCESS_KEY", name: "AWS Access Key", regex: /\b(AKIA[0-9A-Z]{16})\b/g },
  { id: "ANTHROPIC_KEY", name: "Anthropic API Key", regex: /\b(sk-ant-[a-zA-Z0-9_\-]{20,80})\b/g },
  { id: "GITHUB_PAT", name: "GitHub Personal Access Token", regex: /\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})\b/g },
  { id: "SLACK_TOKEN", name: "Slack Bot Token", regex: /\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b/g },
  { id: "STRIPE_KEY", name: "Stripe Live Secret Key", regex: /\b(sk_live_[0-9a-zA-Z]{24,34})\b/g },
  { id: "PROC_ENVIRON", name: "/proc/self/environ Read", regex: /(?:\/proc\/(?:self|\d+)\/environ|\.e["']?n["']?v)/gi },
];

let statusBarItem: vscode.StatusBarItem;
let diagnosticCollection: vscode.DiagnosticCollection;
let leakCount = 0;

export function activate(context: vscode.ExtensionContext) {
  // 1. Initialize Status Bar Defense Indicator
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBarItem.command = "agentshield.showStatusMenu";
  updateStatusBar(0);
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  // 2. Initialize Real-Time Diagnostic Collection
  diagnosticCollection = vscode.languages.createDiagnosticCollection("agentshield");
  context.subscriptions.push(diagnosticCollection);

  // 3. Scan active document on open, change, and save
  if (vscode.window.activeTextEditor) {
    scanDocument(vscode.window.activeTextEditor.document);
  }

  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((event) => scanDocument(event.document)),
    vscode.workspace.onDidOpenTextDocument((doc) => scanDocument(doc)),
    vscode.workspace.onDidCloseTextDocument((doc) => diagnosticCollection.delete(doc.uri))
  );

  // 4. Register Extension Commands
  context.subscriptions.push(
    vscode.commands.registerCommand("agentshield.showStatusMenu", async () => {
      const selection = await vscode.window.showQuickPick(
        [
          { label: "$(shield) Scan Active File", detail: "Check current file for unmasked credentials" },
          { label: "$(search) Audit Entire Workspace", detail: "Scan all workspace files with AgentShield CLI" },
          { label: "$(play) Open Adversarial Attack Playground", detail: "Test hostile evasion payloads in browser" },
          { label: "$(verified) View Trust Center & SIG Lite", detail: "Inspect SOC 2 Type II and DPDP compliance" },
        ],
        { placeHolder: `AgentShield Defense Status: ${leakCount === 0 ? "Guarded (Zero Leaks)" : `${leakCount} Leaks Detected`}` }
      );

      if (selection) {
        if (selection.label.includes("Scan Active File")) {
          vscode.commands.executeCommand("agentshield.scanActiveFile");
        } else if (selection.label.includes("Audit Entire Workspace")) {
          vscode.commands.executeCommand("agentshield.auditWorkspace");
        } else if (selection.label.includes("Playground")) {
          vscode.commands.executeCommand("agentshield.openPlayground");
        } else if (selection.label.includes("Trust Center")) {
          vscode.commands.executeCommand("agentshield.openTrustCenter");
        }
      }
    }),

    vscode.commands.registerCommand("agentshield.scanActiveFile", () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showInformationMessage("AgentShield: No active file to scan.");
        return;
      }
      const count = scanDocument(editor.document);
      if (count === 0) {
        vscode.window.showInformationMessage("🛡️ AgentShield: No credential leaks found in active file.");
      } else {
        vscode.window.showWarningMessage(`⚠️ AgentShield: Intercepted ${count} unmasked secret(s) in this file!`);
      }
    }),

    vscode.commands.registerCommand("agentshield.auditWorkspace", () => {
      const terminal = vscode.window.createTerminal("AgentShield Audit");
      terminal.show();
      terminal.sendText("npx @ritualdev-lab/agentshield ci --enforce");
    }),

    vscode.commands.registerCommand("agentshield.openPlayground", () => {
      vscode.env.openExternal(vscode.Uri.parse("https://ritualdev.in/playground"));
    }),

    vscode.commands.registerCommand("agentshield.openTrustCenter", () => {
      vscode.env.openExternal(vscode.Uri.parse("https://ritualdev.in/trust"));
    }),

    // 5. Register 1-Click Redact Quick-Fix CodeAction Provider
    vscode.languages.registerCodeActionsProvider(
      { scheme: "file" },
      {
        provideCodeActions(document, range, context) {
          const actions: vscode.CodeAction[] = [];
          for (const diagnostic of context.diagnostics) {
            if (diagnostic.source === "AgentShield") {
              const action = new vscode.CodeAction(
                "🛡️ Redact Secret with AgentShield",
                vscode.CodeActionKind.QuickFix
              );
              action.isPreferred = true;
              action.diagnostics = [diagnostic];
              const edit = new vscode.WorkspaceEdit();
              const salt = Math.random().toString(36).substring(2, 8);
              const mask = `[AGENTSHIELD_REDACTED:${diagnostic.code || "SECRET"}:${salt}]`;
              edit.replace(document.uri, diagnostic.range, mask);
              action.edit = edit;
              actions.push(action);
            }
          }
          return actions;
        },
      },
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
    )
  );

  console.log("AgentShield VS Code / Cursor extension active.");
}

function updateStatusBar(count: number) {
  leakCount = count;
  if (count === 0) {
    statusBarItem.text = "$(shield) AgentShield: Guarded";
    statusBarItem.tooltip = "AgentShield: Zero-leak secret defense active. Workspace safe.";
    statusBarItem.backgroundColor = undefined;
  } else {
    statusBarItem.text = `$(alert) AgentShield: ${count} Leaks!`;
    statusBarItem.tooltip = `AgentShield: Detected ${count} unredacted secret(s)! Click to review findings.`;
    statusBarItem.backgroundColor = new vscode.ThemeColor("statusBarItem.errorBackground");
  }
}

function scanDocument(document: vscode.TextDocument): number {
  if (document.uri.scheme !== "file" && document.uri.scheme !== "untitled") {
    return 0;
  }

  const text = document.getText();
  const diagnostics: vscode.Diagnostic[] = [];

  for (const detector of SECRET_DETECTORS) {
    detector.regex.lastIndex = 0;
    let match: RegExpExecArray | null;

    while ((match = detector.regex.exec(text)) !== null) {
      const startPos = document.positionAt(match.index);
      const endPos = document.positionAt(match.index + match[0].length);
      const range = new vscode.Range(startPos, endPos);

      const diagnostic = new vscode.Diagnostic(
        range,
        `[AgentShield Zero-Leak Guard] Unmasked ${detector.name} detected. Avoid committing or passing raw credentials to AI coding agents.`,
        vscode.DiagnosticSeverity.Warning
      );
      diagnostic.source = "AgentShield";
      diagnostic.code = detector.id;
      diagnostics.push(diagnostic);
    }
  }

  diagnosticCollection.set(document.uri, diagnostics);
  updateStatusBar(diagnostics.length);
  return diagnostics.length;
}

export function deactivate() {
  if (diagnosticCollection) {
    diagnosticCollection.clear();
  }
}

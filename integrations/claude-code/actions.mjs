// How a Claude Code tool call is named in a record. The names are from the
// format's shared list (spec/provared-format.md, section 16), so that any
// checker knows what they mean. The naming is done here, by the hook, which
// the agent cannot change: an agent names its action honestly or not at all,
// and this file is the "honestly".
//
// Tools that only talk to the person or to the model itself (a question, a
// plan, a list of tasks) are not recorded: they read and change nothing.

// A command that removes something, in the shells Claude Code uses here.
const DESTROYS = [
  /(^|[\s;&|(])rm\s/, // rm, rm -r, rm -rf
  /(^|[\s;&|(])rmdir\s/,
  /(^|[\s;&|(])del\s/i,
  /\bRemove-Item\b/i,
  /\bgit\s+(reset\s+--hard|clean\b|branch\s+-D\b|push\b.*(--force|-f\b)|tag\s+-d\b)/,
  /\bDROP\s+(TABLE|DATABASE)\b/i,
  /\bunlink\s/,
  /\btruncate\s/,
];

// A command that publishes or releases something to others.
const RELEASES = [
  /\bgit\s+push\b/,
  /\bnpm(\.cmd)?\s+publish\b/,
  /\btwine\s+upload\b/,
  /\bgh\s+release\s+(create|upload|edit)\b/,
  /\bgh\s+repo\s+edit\b/,
  /\bgh\s+pr\s+(create|merge)\b/,
];

/**
 * The action name for a tool call, or null where the call is not recorded.
 * @param {string} toolName
 * @param {any} toolInput
 * @returns {string|null}
 */
export function actionFor(toolName, toolInput) {
  const name = String(toolName ?? '');
  if (/^mcp__/.test(name)) return 'provared.code.run';
  switch (name) {
    case 'Read':
    case 'Grep':
    case 'Glob':
    case 'LS':
    case 'NotebookRead':
      return 'provared.code.read';
    case 'Edit':
    case 'Write':
    case 'MultiEdit':
    case 'NotebookEdit':
      return 'provared.code.change';
    case 'WebFetch':
    case 'WebSearch':
      return 'provared.web.read';
    case 'Agent':
    case 'Task':
    case 'Workflow':
      return 'provared.agent.instruct';
    case 'Bash':
    case 'PowerShell':
      return commandAction(toolInput && typeof toolInput === 'object' ? toolInput.command : undefined);
    default:
      return null;
  }
}

/** The action name for a shell command: a deletion, a release, or a run. */
export function commandAction(command) {
  const text = typeof command === 'string' ? command : '';
  if (DESTROYS.some((re) => re.test(text))) return 'provared.data.delete';
  if (RELEASES.some((re) => re.test(text))) return 'provared.code.release';
  return 'provared.code.run';
}

/** The tools whose calls are recorded, for the hook's matcher. */
export const RECORDED_TOOLS = ['Read', 'Grep', 'Glob', 'LS', 'NotebookRead', 'Edit', 'Write', 'MultiEdit', 'NotebookEdit', 'WebFetch', 'WebSearch', 'Agent', 'Task', 'Workflow', 'Bash', 'PowerShell'];

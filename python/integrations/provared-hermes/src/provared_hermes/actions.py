# How a Hermes tool call is named in a record. The names are from the
# format's shared list (spec/provared-format.md, section 16), so that any
# checker knows what they mean. The naming is done here, by the plugin, which
# the agent cannot change: an agent names its action honestly or not at all,
# and this file is the "honestly".
#
# Every tool is recorded, those of MCP servers and connectors and those not
# known here included, except a short list of tools that only talk to the
# person or change what the model itself holds (a question, a list of tasks,
# the catalogue of tools, the instructions of a skill). A tool not known here
# is named as running a program, the widest of the names, so that a new tool
# is checked and recorded rather than let through.
#
# The same rules as the recorder beside Claude Code (actions.mjs in
# integrations/claude-code of the repository), for Hermes's own tools.

from .commands import command_action

__all__ = ['NOT_RECORDED', 'TOOL_ACTIONS', 'action_for', 'command_action']

NOT_RECORDED = frozenset({
    'clarify',        # a question to the person
    'setup_choose',   # a choice put to the person
    'todo_list',      # the model's own list of tasks
    'tool_search',    # the catalogue of tools
    'tool_describe',
    'tool_call',      # the wrapper of a batch: each call in it is recorded as itself
    'skills_list',    # the instructions of a skill, loaded into the model
    'skill_view',
    'show_tip',       # shown to the person on the desktop
    'gui_tour',
})
"""The tools that are not recorded: each only talks to the person, or
changes what the model itself holds."""

TOOL_ACTIONS = {
    'read_file': 'provared.data.read',
    'read_terminal': 'provared.data.read',
    'read_window_below': 'provared.data.read',
    'vision_analyze': 'provared.data.read',
    'video_analyze': 'provared.data.read',
    'search_files': 'provared.data.search',
    'session_search': 'provared.data.search',
    'write_file': 'provared.data.change',
    'patch': 'provared.data.change',
    'memory': 'provared.data.change',
    'skill_manage': 'provared.data.change',
    'image_generate': 'provared.data.create',
    'video_generate': 'provared.data.create',
    'text_to_speech': 'provared.data.create',
    'web_search': 'provared.web.read',
    'web_extract': 'provared.web.read',
    'x_search': 'provared.web.read',
    'browser_navigate': 'provared.web.read',
    'browser_snapshot': 'provared.web.read',
    'browser_back': 'provared.web.read',
    'browser_scroll': 'provared.web.read',
    'browser_get_images': 'provared.web.read',
    'browser_vision': 'provared.web.read',
    'browser_console': 'provared.web.read',
    'delegate_task': 'provared.agent.instruct',
    'message_agent': 'provared.agent.instruct',
    'a2a_call': 'provared.agent.instruct',
    'a2a_orchestrate': 'provared.agent.instruct',
    'cronjob_manage': 'provared.system.configure',
    'manage_connections': 'provared.system.configure',
    'manage_catalog': 'provared.system.configure',
    'setup_mcp': 'provared.system.configure',
    'execute_code': 'provared.code.run',
    'process_manage': 'provared.code.run',
}
"""Hermes's own tools, by the action each takes. "terminal" is named by its
command (command_action, in commands.py); any tool not here, and not in NOT_RECORDED, runs a
program as far as the record knows: provared.code.run."""

WIDEST = 'provared.code.run'


def action_for(tool_name, args, overrides=None):
    """The action name for a tool call, or None where the call is not recorded.
    overrides: the person's own names for some tools (a dict of tool name to
    action name), which win over the names here; they cannot stop a tool from
    being recorded."""
    name = str(tool_name or '')
    if name in NOT_RECORDED:
        return None
    if overrides and name in overrides:
        return overrides[name]
    if name == 'terminal':
        return command_action(args.get('command') if isinstance(args, dict) else None)
    return TOOL_ACTIONS.get(name, WIDEST)

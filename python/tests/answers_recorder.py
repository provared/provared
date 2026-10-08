# Shared test cases: how each kind of case is answered by this library.
# The stub writer beside an agent and the connector for an agent's tools,
# played as scenarios (scenarios.py). The library is loaded only when a
# case is answered.


def _recorder_scenario(c):
    from scenarios import play_scenario

    return {'ok': play_scenario(c)}


ANSWER = {
    'recorderScenario': _recorder_scenario,
}

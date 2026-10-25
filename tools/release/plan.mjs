// Works out what a release run publishes, by asking each registry what it
// already holds.
//
//   node tools/release/plan.mjs
//
// For npm: the package "provared" at the version in package.json. For the
// Python Package Index: each of the three Python projects (the library and
// the two framework packages), each at the version in its own
// pyproject.toml. A version the registry already holds is not published
// again; this is how the framework packages are left alone on a release
// in which their version did not change, and how a run that stopped part
// of the way can be started again without publishing anything twice.
//
// It writes, for the next steps of the workflow:
//   npm            "publish" or "present"
//   python         the folders of the Python projects to publish, as a
//                  JSON list (the library first), possibly empty
//   python_present the folders of the Python projects already published
//                  at their version, as a JSON list; the build compares
//                  each with what is on the index
//   python_names   the Python projects to publish, as "name version"
//                  separated by commas, for the release notes
//   python_kept    the same, for the Python projects already published

import { npmPackage, pythonProject, PYTHON_PROJECTS, setOutput, fail } from './lib.mjs';
import { registryHas } from './registry-has.mjs';

try {
  const npm = npmPackage();
  const npmPresent = await registryHas('npm', npm.name, npm.version);
  console.log(`npm: ${npm.name} ${npm.version} is ${npmPresent ? 'already published; it is not published again' : 'not published yet; it will be published'}.`);

  const publish = [];
  const present = [];
  for (const folder of PYTHON_PROJECTS) {
    const project = pythonProject(folder);
    const has = await registryHas('pypi', project.name, project.version);
    console.log(`Python Package Index: ${project.name} ${project.version} is ${has ? 'already published; it is not published again' : 'not published yet; it will be published'}.`);
    (has ? present : publish).push(project);
  }

  setOutput('npm', npmPresent ? 'present' : 'publish');
  setOutput('python', JSON.stringify(publish.map((p) => p.folder)));
  setOutput('python_present', JSON.stringify(present.map((p) => p.folder)));
  setOutput('python_names', publish.map((p) => `${p.name} ${p.version}`).join(','));
  setOutput('python_kept', present.map((p) => `${p.name} ${p.version}`).join(','));
} catch (error) {
  fail(error.message);
}

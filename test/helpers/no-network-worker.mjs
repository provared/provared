// For test/no-network.test.mjs: a worker that runs the code it is given as
// if written in the file it names, so that the code's frames name that file.

import net from 'node:net';
import vm from 'node:vm';
import { workerData } from 'node:worker_threads';

globalThis.net = net;
vm.runInThisContext(workerData.code, { filename: workerData.filename });

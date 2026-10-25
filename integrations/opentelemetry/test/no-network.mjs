// A guard that refuses every connection this test process could make: to
// the network, to a name service, and to this computer's own ports. The
// tests import it first. Each refusal is kept in "refused", and the tests
// check, at the end, that nothing was refused, so that a connection tried
// and swallowed by a library is still seen.
//
// OpenTelemetry's SDK sends nothing unless an exporter that sends is set
// up; the tests use its in-memory exporter. This guard makes sure.

import dgram from 'node:dgram';
import dns from 'node:dns';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import { syncBuiltinESMExports } from 'node:module';

export const refused = [];

function refuse(what) {
  return function refusedCall() {
    refused.push(what);
    throw new Error(`The test guard refused a connection: ${what}.`);
  };
}

net.Socket.prototype.connect = refuse('net.Socket.connect');
for (const name of ['connect', 'createConnection']) net[name] = refuse(`net.${name}`);
tls.connect = refuse('tls.connect');
for (const module of [http, https]) {
  const label = module === http ? 'http' : 'https';
  module.request = refuse(`${label}.request`);
  module.get = refuse(`${label}.get`);
}
for (const name of ['lookup', 'lookupService', 'resolve', 'resolve4', 'resolve6', 'resolveAny', 'resolveCname', 'resolveMx', 'resolveNs', 'resolveSrv', 'resolveTxt', 'reverse']) {
  if (typeof dns[name] === 'function') dns[name] = refuse(`dns.${name}`);
  if (dns.promises && typeof dns.promises[name] === 'function') dns.promises[name] = refuse(`dns.promises.${name}`);
}
dgram.Socket.prototype.send = refuse('dgram.Socket.send');
dgram.Socket.prototype.connect = refuse('dgram.Socket.connect');
globalThis.fetch = refuse('fetch');
if (typeof globalThis.WebSocket === 'function') globalThis.WebSocket = refuse('WebSocket');
// So that code that imports these by name (import { connect } from 'node:net') meets the guard too.
syncBuiltinESMExports();

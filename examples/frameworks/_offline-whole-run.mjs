// Loaded with --import (see "npm start" and "npm test" in package.json):
// opens the guard of _offline.mjs before any other module is loaded, and
// keeps it open until the process ends.
import { holdOffline } from './_offline.mjs';

holdOffline();

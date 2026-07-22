#!/usr/bin/env node
import { createProgram } from '../src/cli/commands.js';

try {
  await createProgram().parseAsync(process.argv);
} catch (error) {
  process.stderr.write(`asvp-agent: ${error.message}\n`);
  process.exitCode = 1;
}

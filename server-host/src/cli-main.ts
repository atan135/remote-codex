#!/usr/bin/env node
import { runServerHostCli } from "./cli.js";

process.exitCode = await runServerHostCli(process.argv.slice(2));

#!/usr/bin/env node
import { runEdgeClientHostCli } from "./cli.js";

process.exitCode = await runEdgeClientHostCli(process.argv.slice(2));

#!/usr/bin/env node
import { runEgressAgentHostCli } from "./cli.js";

process.exitCode = runEgressAgentHostCli(process.argv.slice(2));
